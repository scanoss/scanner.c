// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/scanner.c
 *
 * A simple SCANOSS client in C for direct file scanning
 *
 * Copyright (C) 2018-2020 SCANOSS.COM
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#define _GNU_SOURCE
#include <ctype.h>
#include <openssl/bio.h>
#include <openssl/md5.h>
#include <openssl/ssl.h>
#include <dirent.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <sys/time.h>
#include <math.h>
#include "scanner.h"
#include "blacklist_ext.h"
#include "winnowing.h"
#include "log.h"
/*SCANNER PRIVATE PROPERTIES*/


#define MAX_FILES_CHUNK (1<<31)

#define DEFAULT_WFP_SCAN_FILE_NAME "scan.wfp"
#define DEFAULT_RESULT_NAME "scanner_output.txt"

const char EXCLUDED_DIR[] = ".git, .svn, .eggs, __pycache__, node_modules,";
const char EXCLUDED_EXTENSIONS[] = ".1, .2, .3, .4, .5, .6, .7, .8, .9, .ac, .adoc, .am,"
	                                ".asciidoc, .bmp, .build, .cfg, .chm, .class, .cmake, .cnf,"
	                                ".conf, .config, .contributors, .copying, .crt, .csproj, .css,"
	                                ".csv, .cvsignore, .dat, .data, .doc, .ds_store, .dtd, .dts,"
	                                ".dtsi, .dump, .eot, .eps, .geojson, .gdoc, .gif, .gitignore,"
	                                ".glif, .gmo, .gradle, .guess, .hex, .htm, .html, .ico, .in,"
                                    ".inc, .info, .ini, .ipynb, .jpeg, .jpg, .json, .jsonld,"
                                    ".log, .m4, .map, .markdown, .md, .md5, .meta, .mk, .mxml,"
                                    ".o, .otf, .out, .pbtxt, .pdf, .pem, .phtml, .plist, .png,"
                                    ".po, .ppt, .prefs, .properties, .pyc, .qdoc, .result, .rgb,"
                                    ".rst, .scss, .sha, .sha1, .sha2, .sha256, .sln, .spec, .sql,"
                                    ".sub, .svg, .svn-base, .tab, .template, .test, .tex, .tiff,"
                                    ".toml, .ttf, .txt, .utf-8, .vim, .wav, .whl, .woff, .xht,"
                                    ".xhtml, .xls, .xml, .xpm, .xsd, .xul, .yaml, .yml,";


static int curl_request(int api_req, char* data,scanner_object_t *s);

/* Returns a hexadecimal representation of the first "len" bytes in "bin" */
static char *bin_to_hex(uint8_t *bin, uint32_t len)
{
    char digits[] = "0123456789abcdef";
    char *out = malloc(2 * len + 1);
    uint32_t ptr = 0;

    for (uint32_t i = 0; i < len; i++)
    {
        out[ptr++] = digits[(bin[i] & 0xF0) >> 4];
        out[ptr++] = digits[bin[i] & 0x0F];
    }

    out[ptr] = 0;
    return out;
}

static char *read_file(char *path, long *length)
{
    /* Read file into memory */
    FILE *fp = fopen(path, "rb");
    fseek(fp, 0, SEEK_END);
    *length = ftell(fp);
    char *src = calloc(*length + 1, 1);
    fseek(fp, 0, SEEK_SET);
    fread(src, 1, *length, fp);
    fclose(fp);
    return src;
}


static long millis()
{
    struct timespec _t;
    clock_gettime(CLOCK_REALTIME, &_t);
    return _t.tv_sec*1000 + lround(_t.tv_nsec/1.0e6);
}

static void wfp_capture(scanner_object_t *scanner, char *path, char *wfp_buffer)
{
    /* Skip unwanted extensions */
    long length = 0;
    char *src = read_file(path, &length);

    scanner->status.state = SCANNER_STATE_WFP_CALC; //update scanner state

    /* Skip if file is under threshold or if content is not wanted*/
    if (length < MIN_FILE_SIZE || unwanted_header(src))
    {
        free(src);
        return;
    }

    /* Calculate MD5 */
    uint8_t bin_md5[16] = "\0";
    MD5((uint8_t *)src, length, bin_md5);
    char *hex_md5 = bin_to_hex(bin_md5, 16);

    /* Save file information to buffer */
    sprintf(wfp_buffer + strlen(wfp_buffer), "file=%s,%lu,%s\n", hex_md5, length, path);
    free(hex_md5);
    scanner->status.wfp_files++; //update scanner proc. files
    

    /* If it is not binary (chr(0) found), calculate snippet wfps */
    if (strlen(src) == length && length < MAX_FILE_SIZE)
    {
        /* Capture hashes (Winnowing) */
        uint32_t *hashes = malloc(MAX_FILE_SIZE);
        uint32_t *lines = malloc(MAX_FILE_SIZE);
        uint32_t last_line = 0;

        /* Calculate hashes */
        uint32_t size = winnowing(src, hashes, lines, MAX_FILE_SIZE);

        /* Write hashes to buffer */
        for (int i = 0; i < size; i++)
        {
            if (last_line != lines[i])
            {
                if (last_line != 0)
                    strcat(wfp_buffer, "\n");
                sprintf(wfp_buffer + strlen(wfp_buffer), "%d=%08x", lines[i], hashes[i]);
                last_line = lines[i];
            }
            else
                sprintf(wfp_buffer + strlen(wfp_buffer), ",%08x", hashes[i]);
        }
        strcat(wfp_buffer, "\n");
        free(hashes);
        free(lines);
        
        if (scanner->callback && scanner->status.wfp_files % 100 == 0)
        {
            scanner->callback(&scanner->status,SCANNER_EVT_WFP_CALC_IT);
        }  
            
    }
    free(src);
}

static bool scanner_is_dir(char *path)
{
    struct stat pstat;
    if (!stat(path, &pstat))
        if (S_ISDIR(pstat.st_mode))
            return true;
    return false;
}

static bool scanner_is_file(char *path)
{
    struct stat pstat;
    if (!stat(path, &pstat))
        if (S_ISREG(pstat.st_mode))
            return true;
    return false;
}

/* Scan a file */
static bool scanner_file_proc(scanner_object_t *s,char *path)
{
    bool state = true;
    char *wfp_buffer;
    char *ext = strrchr(path, '.');
    if (!ext)
        return state;

    char f_extension[strlen(ext) + 2];

    /*File extension filter*/
    sprintf(f_extension, "%s,", ext);

    if (strstr(EXCLUDED_EXTENSIONS, f_extension))
    {
        log_trace("Excluded extension: %s", ext);
        return true; //avoid filtered extensions
    }

    wfp_buffer = calloc(MAX_FILE_SIZE, 1);

    *wfp_buffer = 0;

    wfp_capture(s,path, wfp_buffer);
    if (*wfp_buffer)
    {
        FILE *wfp_f = fopen(s->wfp_path, "a+");
        fprintf(wfp_f, "%s", wfp_buffer);
        fclose(wfp_f);
        state = false;
    }
    else
    {
        log_trace("No wfp: %s", path);
    }

    free(wfp_buffer);
    return state;
}

static bool get_last_component(char * buffer, char * component)
{
    bool state = true;

    char * last = buffer;
    const char key[] = "\"component\":";

    while (last < buffer + strlen(buffer) && last != NULL)
    {
        last = strstr(last, key);
        
        if (last)
        {
            char * comp_first_letter = strchr(last,':') + 2;
            
            if (*comp_first_letter != ' ')
            {
                char * comp_last_letter = strchr(last,',');
                memset(component,0,MAX_COMPONENT_SIZE);
                strncpy(component,comp_first_letter+1,comp_last_letter-comp_first_letter-2);
                state = false;
            }

            last += strlen(key);   
        }

    }
    return state;
}

void json_correct(char * target)
{
    size_t file_length = strlen(target);
     
    char buffer[file_length];
    char *insert_point = &buffer[0];
    const char *tmp = target;

    char * needle;
    char * replacement;

    asprintf(&needle,"}\n\r\n{");
    asprintf(&replacement,"\n\r,\r\n");

    size_t needle_len = strlen(needle);
    size_t repl_len = strlen(replacement);   

    while (1) {
        const char *p = strstr(tmp, needle);

        // walked past last occurrence of needle; copy remaining part
        if (p == NULL) 
        {
            strcpy(insert_point, tmp);
            break;
        }

        // copy part before needle
        memcpy(insert_point, tmp, p - tmp);
        insert_point += p - tmp;

        // copy replacement string
        memcpy(insert_point, replacement, repl_len);
        insert_point += repl_len;

        // adjust pointers, move on
        tmp = p + needle_len;
    }
    memset(target,0,file_length);
    strcpy(target,buffer);
    free(needle);
    free(replacement);
}


static bool scan_request_by_chunks(scanner_object_t *s)
{
#define START_FIND_COMP_FROM_END 36864

    const char file_key[] = "file=";
    bool state = true;
    
    int files_count = 0;
    
    long buffer_size = 0; //size of wfp file
    char *wfp_buffer = read_file(s->wfp_path, &buffer_size);
    wfp_buffer[buffer_size] = 0;
    
    char * last_file = wfp_buffer;
    char * last_chunk = wfp_buffer;
    
    char post_response_buffer[START_FIND_COMP_FROM_END+1];
    int post_response_pos = 0;
    long chunk_start_time = 0;
    fpos_t file_pos;
    /*Patch for json join of no-plain formats*/
    if(!strstr(s->format,"plain"))
    {
        s->files_chunk_size = MAX_FILES_CHUNK;
        log_debug("Avoid chuck proc for %s format: %u",s->format,s->files_chunk_size);
    }
    s->status.state = SCANNER_STATE_ANALIZING;
    log_debug("ID: %s - Scanning, it could take some time, please be patient",s->status.id);
    //walk over wfp buffer search for file key
    s->status.total_response_time = millis();
    while(last_file - wfp_buffer < buffer_size)
    {      
        chunk_start_time = millis();
        last_file = strstr(last_file,file_key);
        if (last_file)
        {
            files_count++;
        }

        if (files_count % s->files_chunk_size == 0|| (last_file == NULL))
        {
            if (last_file == NULL)
                last_file = &wfp_buffer[buffer_size];
            //exact a new chunk from wfp file
            char *chunk_buffer = calloc(last_file - last_chunk + 1, 1);
            strncpy(chunk_buffer,last_chunk,last_file - last_chunk);
            s->status.scanned_files = files_count; //update proc. files
            last_chunk = last_file;
            //define the component context, find the last component in the output file.
            post_response_pos = ftell(s->output);
            
            memset(post_response_buffer,0,sizeof(post_response_buffer));
            
            if (post_response_pos < START_FIND_COMP_FROM_END)
            {
                fseek(s->output,0L,SEEK_SET);
            }
            else
            {
                fseek(s->output,-1*START_FIND_COMP_FROM_END,SEEK_END);
            }
            
            //go back in the output file and find the last component
            fread(post_response_buffer,1,START_FIND_COMP_FROM_END,s->output);
            get_last_component(post_response_buffer,s->status.component_last);
            
            log_debug("Last found component: %s", s->status.component_last);
            
            fseek(s->output,0L,SEEK_END);
        
            //get the result from the last chunk - It will be append to the output file
            fgetpos(s->output, &file_pos);
            curl_request(API_REQ_POST,chunk_buffer,s);

            //correct json errors due to chunk proc.
            if (s->status.scanned_files > s->files_chunk_size)
            {
               // fsetpos(s->output,&file_pos);
                int offset = post_response_pos-ftell(s->output)-128;
                fseek(s->output,offset,SEEK_END);
                memset(post_response_buffer,0,strlen(post_response_buffer));
                fread(post_response_buffer,1,156,s->output);
                
                json_correct(post_response_buffer);
                
                fseek(s->output,offset,SEEK_END);
                fwrite(post_response_buffer,1,strlen(post_response_buffer),s->output);
                fseek(s->output,0L,SEEK_END);
            }

            free(chunk_buffer);
            state = false;
            s->status.last_chunk_response_time = millis() - chunk_start_time; 
            log_debug("ID: %s - Chunk proc. end, %u processed files in %ld ms", s->status.id, s->status.scanned_files,millis() - s->status.total_response_time);
            sprintf(s->status.message, "CHUNK_PROC_%lu_ms", s->status.last_chunk_response_time);
            if (s->callback)
            {
                s->callback(&s->status,SCANNER_EVT_CHUNK_PROC);
            } 
        }

        last_file += strlen(file_key);
    }
    s->status.total_response_time = millis() - s->status.total_response_time;

    if (s->callback)
    {
        s->callback(&s->status,SCANNER_EVT_CHUNK_PROC_END);
    }
    
    free(s->wfp_path);  
    s->status.state = SCANNER_STATE_OK;
    return state;

}

/* Scan all files from a Directory*/
static bool scanner_dir_proc(scanner_object_t *s, char *path)
{

    bool state = true; //true if were a error

    DIR *d = opendir(path);
    if (d == NULL)
        return false;
    struct dirent *entry; // for the directory entries

    //remove "./" from path
    if (path[0] == '.' && path[1] == '/')
    {
        path+=2;
    }

    while ((entry = readdir(d)) != NULL)
    {
        char temp[strlen(path) + strlen(entry->d_name) + 1];
        
        sprintf(temp, "%s/%s", path, entry->d_name);

        if (scanner_is_dir(temp))
        {

            if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, ".."))
                continue;

            /*Directory filter */
            char f_dir[strlen(entry->d_name) + 2];
            sprintf(f_dir, "%s,", entry->d_name);
            if (strstr(EXCLUDED_DIR, f_dir))
            {
                log_trace("Excluded Directory: %s", entry->d_name);
                continue;
            }
            scanner_dir_proc(s, temp); //If its a valid directory, then process it
        }
        else if (scanner_is_file(temp))
        {
            if (!scanner_file_proc(s ,temp))
            {
                log_trace("Scan: %s", temp);
            }
            state = false;
        }
    }

    closedir(d);
    return state;
}


static int curl_request(int api_req, char* data, scanner_object_t *s)
{
    char *m_host;
    char *user_version;
    char *user_session;
    //char *context;

    long m_port = strtol(s->API_port, NULL, 10);
    
    asprintf(&user_session, "X-session: %s", s->API_session);
    asprintf(&user_version, "User-Agent: SCANOSS_scanner.c/%s", VERSION);
    //asprintf(&context,"context: %s", scanner->status.component_last);
    
    if (api_req == API_REQ_POST)
        asprintf(&m_host, "%s/scan/direct", s->API_host);

    else
        asprintf(&m_host,"%s/file_contents/%s",s->API_host,data);
    
    CURL *curl;
    CURLcode res;
    /* In windows, this will init the winsock stuff */
    res = curl_global_init(CURL_GLOBAL_DEFAULT);
    /* Check for errors */
    if (res != CURLE_OK)
    {
        log_fatal("curl_global_init() failed: %s\n",
                curl_easy_strerror(res));
        return 1;
    }

    /* get a curl handle */
    curl = curl_easy_init();
    if (curl)
    {
        /* First set the URL that is about to receive our POST. */
        curl_easy_setopt(curl, CURLOPT_URL, m_host);
        curl_easy_setopt(curl, CURLOPT_PORT, m_port);
       
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, s->output);
     
        if (log_level_is_enabled(LOG_TRACE))
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

        struct curl_slist *chunk = NULL;
        chunk = curl_slist_append(chunk, "Connection: close");
        chunk = curl_slist_append(chunk, user_version);
        chunk = curl_slist_append(chunk, user_session);
        //chunk = curl_slist_append(chunk, context);
        chunk = curl_slist_append(chunk, "Expect:");
        chunk = curl_slist_append(chunk, "Accept: */*");

        res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

        if (api_req == API_REQ_POST)
        {
            curl_mime *mime;
            curl_mimepart *part;
            mime = curl_mime_init(curl);
            
            part = curl_mime_addpart(mime);
            curl_mime_name(part, "format");
            curl_mime_data(part, s->format, CURL_ZERO_TERMINATED);

            part = curl_mime_addpart(mime);
            curl_mime_name(part, "context");
            curl_mime_data(part, s->status.component_last, CURL_ZERO_TERMINATED);
            
            part = curl_mime_addpart(mime);
            curl_mime_name(part, "file");
            curl_mime_filename(part, "scan.wfp");
            curl_mime_type(part,"application/octet-stream");
            curl_mime_data(part, data, CURL_ZERO_TERMINATED);

            curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
        }
    
        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        
        /* Check for errors */
        if (res != CURLE_OK)
        {
            log_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
            if (s->callback)
            {
                s->callback(&s->status,SCANNER_EVT_ERROR_CURL);
            }
        }

        /* always cleanup */
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }

    curl_global_cleanup();
    
    free(m_host);
    free(user_session);
    free(user_version);
   // free(context);

    return 0;

}
/********* PUBLIC FUNTIONS DEFINITION ************/

void scanner_set_format(scanner_object_t *s, char *form)
{
    if (!form)
        return;
        
    if (strstr(form, "plain") || strstr(form, "spdx") || strstr(form, "cyclonedx"))
    {
        strncpy(s->format, form, sizeof(s->format));
    }
    else
        log_debug("%s is not a valid output format, using plain\n", form);
}

void scanner_set_host(scanner_object_t *s, char *host)
{
    if (!host || strcmp(host," ") == 0)
        return;

    memset(s->API_host, '\0', sizeof(s->API_host));
    strncpy(s->API_host, host, sizeof(s->API_host));
    log_debug("Host set: %s", s->API_host);
}

void scanner_set_port(scanner_object_t *s, char *port)
{
    if (!port || strcmp(port," ") == 0)
        return;

    memset(s->API_port, '\0', sizeof(s->API_port));
    strncpy(s->API_port, port, sizeof(s->API_port));
    log_debug("Port set: %s", s->API_port);
}

void scanner_set_session(scanner_object_t *s, char *session)
{
    if (!session || strcmp(session," ") == 0)
        return;

    memset(s->API_session, '\0', sizeof(s->API_session));
    strncpy(s->API_session, session, sizeof(s->API_session));
    log_debug("Session set: %s", s->API_session);
}

void scanner_set_log_level(int level)
{
    log_set_level(level);
}

void scanner_set_log_file(char *log)
{
    log_set_file(log);
}

void scanner_set_output(scanner_object_t * e, char * f)
{
    if (!f)
    {
       asprintf(&e->output_path,"%s", DEFAULT_RESULT_NAME); 
    }
    else
        e->output_path = f;

    asprintf(&e->wfp_path,"%s.wfp",e->output_path);
    e->output = fopen(e->output_path, "w+");
    log_debug("ID: %s -File open: %s", e->status.id, e->output_path);
}

int scanner_recursive_scan(scanner_object_t * scanner)
{  
    if (!scanner)
    {
        log_fatal("Scanner object need to proceed");
    }
    scanner->status.state = SCANNER_STATE_INIT;
    scanner->status.wfp_files = 0;
    scanner->status.scanned_files = 0;
    scanner->status.wfp_total_time = millis();    
    scanner->status.last_chunk_response_time = 0;
    scanner->status.total_response_time = 0;
    strcpy(scanner->status.message, "WFP_CALC_START\0");
    log_debug("ID: %s - Scan start - WFP Calculation", scanner->status.id);
    if (scanner->callback)
    {
        scanner->callback(&scanner->status,SCANNER_EVT_START);
    } 
    //check if exist the output file
    if (!scanner->output)
        scanner_set_output(scanner, NULL);
      
    /*create blank wfp file*/
    FILE *wfp_f = fopen(scanner->wfp_path, "w+");
    fclose(wfp_f);

    if (scanner_is_file(scanner->scan_path))
    {
        scanner_file_proc(scanner, scanner->scan_path);
    }
    else if (scanner_is_dir(scanner->scan_path))
    {
        int path_len = strlen(scanner->scan_path);
        if (path_len > 1 && scanner->scan_path[path_len - 1] == '/') //remove extra '/'
            scanner->scan_path[path_len - 1] = '\0';
        
        scanner_dir_proc(scanner, scanner->scan_path);
    }
    else
    {
        scanner->status.state = SCANNER_STATE_ERROR;
        log_error("\"%s\" is not a file\n", scanner->scan_path);
        if (scanner->callback)
        {
            scanner->callback(&scanner->status,SCANNER_EVT_ERROR);
        }
    }
    scanner->status.wfp_total_time = millis() - scanner->status.wfp_total_time;
    log_debug("ID: %s - WFP calculation end, %u processed files in %ld ms", scanner->status.id, scanner->status.wfp_files, scanner->status.wfp_total_time);
    if (scanner->callback)
    {
        scanner->callback(&scanner->status,SCANNER_EVT_WFP_CALC_END);
    }

    strcpy(scanner->status.message, "WFP_CALC_END\0"); 
    scan_request_by_chunks(scanner);

    if (scanner->output)
        fclose(scanner->output);

    if (scanner->callback)
    {
        scanner->callback(&scanner->status,SCANNER_EVT_END);
    }
    strcpy(scanner->status.message, "FINISHED\0");

    return scanner->status.state;
}

int scanner_get_file_contents(scanner_object_t *scanner, char * hash)
{ 
    int err_code = curl_request(API_REQ_GET,hash,scanner);
    fclose(scanner->output);

    return err_code;
}


bool scanner_umz(char * md5)
{
    scanner_object_t * scanner = scanner_create("0,SCANOSS-CLI",NULL,NULL,NULL,NULL,NULL,NULL, NULL);

    if (scanner->output == NULL)
        scanner->output = stdout;

    int state = curl_request(API_REQ_GET,md5,scanner);
    scanner_object_free(scanner);
    return state;
}


int scanner_print_output(scanner_object_t *scanner)
{
    bool state = true;

    if (!scanner->output_path)
        return 1;

    FILE * output = fopen(scanner->output_path, "r");
    char c;
    
    if (output) 
    {
        while ((c = getc(output)) != EOF)
            putchar(c);
    
        fclose(output);
        state = false;
    }
    
    free(scanner->output_path);
    return state;   
}
scanner_object_t * scanner_create(char * id, char * host, char * port, char * session, char * format, char * path, char * file, scanner_evt_handler callback)
{
     scanner_object_t *scanner = calloc(1, sizeof(scanner_object_t));
     scanner_object_t init = __SCANNER_OBJECT_INIT(path,file);
     init.callback = callback;
     strncpy(init.status.id, id, MAX_ID_LEN);

     //copy default config
     memcpy(scanner,&init,sizeof(scanner_object_t));

    scanner_set_output(scanner, file);
    scanner_set_host(scanner, host);
    scanner_set_port(scanner, port);
    scanner_set_session(scanner, session);
    scanner_set_format(scanner, format);
    strcpy(scanner->status.message, "SCANNER_CREATED\0");
    return scanner;
}

void scanner_object_free(scanner_object_t * scanner)
{
    free(scanner);
}