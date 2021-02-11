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

#include "scanner.h"
#include "blacklist_ext.h"
#include "winnowing.h"
#include "log.h"

/*SCANNER PRIVATE PROPERTIES*/
#define API_HOST_DEFAULT "osskb.org/api"
#define API_PORT_DEFAULT "443"
#define API_SESSION_DEFAULT "\0"

#define MAX_COMPONENT_SIZE 128
#define MAX_FILES_CHUNK (1<<31)
#define DEFAULT_FILES_CHUNK 100

#define WFP_SCAN_FILE_NAME "scan.wfp"
#define DEFAULT_RESULT_NAME "scanner_output.txt"

const char EXCLUDED_DIR[] = ".git, .svn, .eggs, __pycache__, node_modules, vendor,";
const char EXCLUDED_EXTENSIONS[] = ".png, .html, .xml, .svg, .yaml, .yml, .txt, .json, .gif, .md,"
                                   ".test, .cfg, .pdf, .properties, .jpg, .vim, .sql, .result, .template,"
                                   ".tiff, .bmp, .DS_Store, .eot, .otf, .ttf, .woff, .rgb, .conf, .whl, .o, .ico, .wfp,";


static int curl_request(int api_req, char* data, FILE *output);

static char API_host[32] = API_HOST_DEFAULT;
static char API_port[5] = API_PORT_DEFAULT;
static char API_session[33] = API_SESSION_DEFAULT;

static unsigned int files_chunk_size = 100;

static char format[16] = "plain";
static unsigned int proc_files = 0;

static char *output_path = NULL;
FILE *output;

char component_last[MAX_COMPONENT_SIZE] = "NULL";

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

static void wfp_capture(char *path, char *wfp_buffer)
{
    /* Skip unwanted extensions */
    long length = 0;
    char *src = read_file(path, &length);

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

    //char *file_name = path + strlen(root);

    /* Save file information to buffer */
    sprintf(wfp_buffer + strlen(wfp_buffer), "file=%s,%lu,%s\n", hex_md5, length, path);
    free(hex_md5);

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
static bool scanner_file_proc(char *path, FILE *output)
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
        log_debug("Excluded extension: %s", ext);
        return true; //avoid filtered extensions
    }

    wfp_buffer = calloc(MAX_FILE_SIZE, 1);

    *wfp_buffer = 0;

    wfp_capture(path, wfp_buffer);
    if (*wfp_buffer)
    {
        FILE *wfp_f = fopen(WFP_SCAN_FILE_NAME, "a+");
        fprintf(wfp_f, "%s", wfp_buffer);
        fclose(wfp_f);
        state = false;
    }
    else
    {
        log_debug("No wfp: %s", path);
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

void json_correct(FILE *f)
{
    size_t file_length = 0;
    
    fseek(f, 0, SEEK_END);
    file_length = ftell(f);
    char * target = calloc(file_length + 1, 1);
    
    fseek(f, 0, SEEK_SET);
    fread(target, 1, file_length, f);
    
    char buffer[file_length];
    char *insert_point = &buffer[0];
    const char *tmp = target;

    char * needle;
    char * replacement;

   if (strstr(format,"plain")) //|| strstr(format,"cyclonedx"))
    {
        asprintf(&needle,"}\n\r\n{");
        asprintf(&replacement,",");
    }
    else
        return;
    
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

   log_debug("overwriting");
    output=freopen(NULL,"w",output);
    fputs(buffer,output);

    free(target);
    free(needle);
    free(replacement);
}

static bool scan_request_by_chunks()
{
#define START_FIND_COMP_FROM_END 1000

    const char file_key[] = "file=";
    bool state = true;
    
    int files_count = 0;
    
    long buffer_size = 0;
    char *wfp_buffer = read_file(WFP_SCAN_FILE_NAME, &buffer_size);
    wfp_buffer[buffer_size] = 0;
    
    char * last_file = wfp_buffer;
    char * last_chunk = wfp_buffer;
    
    char post_response_buffer[START_FIND_COMP_FROM_END+1];
    int post_response_pos = 0;

    /*Patch for json join of no-plain formats*/
    if(!strstr(format,"plain"))
    {
        files_chunk_size = MAX_FILES_CHUNK;
        log_debug("Avoid chuck proc for %s format: %u",format,files_chunk_size);
    }
    
    while(last_file - wfp_buffer < buffer_size)
    {
        last_file = strstr(last_file,file_key);
        if (last_file)
        {
            files_count++;
        }

        if (files_count > files_chunk_size || (last_file == NULL))
        {
            if (last_file == NULL)
                last_file = &wfp_buffer[buffer_size];

            char *chunk_buffer = calloc(last_file - last_chunk + 1, 1);
            strncpy(chunk_buffer,last_chunk,last_file - last_chunk);
            files_count = 0;
            last_chunk = last_file;
            
            post_response_pos = ftell(output);
            
            memset(post_response_buffer,0,sizeof(post_response_buffer));
            
            if (post_response_pos < START_FIND_COMP_FROM_END)
            {
                fseek(output,0L,SEEK_SET);
            }
            else
            {
                fseek(output,-1*START_FIND_COMP_FROM_END,SEEK_END);
            }
            
            fread(post_response_buffer,1,START_FIND_COMP_FROM_END,output);
            get_last_component(post_response_buffer,component_last);

            log_debug(component_last);
            
            fseek(output,0L,SEEK_END);
            curl_request(API_REQ_POST,chunk_buffer,output);
            free(chunk_buffer);
            state = false;   
        }
        else
        {
            last_file += strlen(file_key);
        }
    }
    
    json_correct(output);
     
    return state;

}

/* Scan all files from a Directory*/
static bool scanner_dir_proc(char *path, FILE *output)
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
                log_debug("Excluded Directory: %s", entry->d_name);
                continue;
            }
            scanner_dir_proc(temp, output); //If its a valid directory, then process it
        }
        else if (scanner_is_file(temp))
        {
            if (!scanner_file_proc(temp, output))
            {
                proc_files++;
                log_trace("Scan: %s", temp);
            }
            state = false;
        }
    }

    closedir(d);
    return state;
}


static int curl_request(int api_req, char* data, FILE *output)
{
    char *m_host;
    char *user_version;
    char *user_session;
    char *context;

    long m_port = strtol(API_port, NULL, 10);
    
    asprintf(&user_session, "X-session: %s", API_session);
    asprintf(&user_version, "User-Agent: SCANOSS_scanner.c/%s", VERSION);
    asprintf(&context,"context: %s", component_last);
    
    if (api_req == API_REQ_POST)
        asprintf(&m_host, "%s/scan/direct", API_host);

    else
        asprintf(&m_host,"%s/file_contents/%s",API_host,data);
    
    CURL *curl;
    CURLcode res;

    /* In windows, this will init the winsock stuff */
    res = curl_global_init(CURL_GLOBAL_DEFAULT);
    /* Check for errors */
    if (res != CURLE_OK)
    {
        fprintf(stderr, "curl_global_init() failed: %s\n",
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
       
        if (api_req == API_REQ_POST)
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, output);
        else
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, output);

        if (log_level_is_enabled(LOG_TRACE))
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

        struct curl_slist *chunk = NULL;
        chunk = curl_slist_append(chunk, "Connection: close");
        chunk = curl_slist_append(chunk, user_version);
        chunk = curl_slist_append(chunk, user_session);
        chunk = curl_slist_append(chunk, context);
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
            curl_mime_data(part, format, CURL_ZERO_TERMINATED);
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
            log_error("curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

        /* always cleanup */
        curl_easy_cleanup(curl);
        curl_slist_free_all(chunk);
    }

    curl_global_cleanup();
    
    free(m_host);
    free(user_session);
    free(user_version);
    free(context);

    return 0;

}
/********* PUBLIC FUNTIONS DEFINITION ************/

void scanner_set_format(char *form)
{
    if (strstr(form, "plain") || strstr(form, "spdx") || strstr(form, "cyclonedx"))
    {
        strncpy(format, form, sizeof(format));
        log_debug(format);
    }
    else
        log_info("%s is not a valid output format, using plain\n", form);
}

void scanner_set_host(char *host)
{
    memset(API_host, '\0', sizeof(API_host));
    strncpy(API_host, host, sizeof(API_host));
    log_debug("Host set: %s", API_host);
}

void scanner_set_port(char *port)
{
    memset(API_port, '\0', sizeof(API_port));
    strncpy(API_port, port, sizeof(API_port));
    log_debug("Port set: %s", API_port);
}

void scanner_set_session(char *session)
{
    memset(API_session, '\0', sizeof(API_session));
    strncpy(API_session, session, sizeof(API_session));
    log_debug("Session set: %s", API_session);
}

void scanner_set_log_level(int level)
{
    log_set_level(level);
}

void scanner_set_log_file(char *log)
{
    log_set_file(log);
}

void scanner_set_output(char * f)
{
    if (!f)
    {
       asprintf(&output_path,"%s", DEFAULT_RESULT_NAME); 
    }
    else
        output_path = f;
 
    output = fopen(output_path, "w+");
}

bool scanner_recursive_scan(char *path)
{
    bool state = true;
    log_debug("Scan start");
    proc_files = 0;
    
    //check if exist the output file
    if (!output)
        scanner_set_output(NULL);

    /*create blank wfp file*/
    FILE *wfp_f = fopen(WFP_SCAN_FILE_NAME, "w+");
    fclose(wfp_f);

    if (scanner_is_file(path))
    {
        scanner_file_proc(path, output);
        state = false;
    }
    else if (scanner_is_dir(path))
    {
        int path_len = strlen(path);
        if (path_len > 1 && path[path_len - 1] == '/') //remove extra '/'
            path[path_len - 1] = '\0';
        
        scanner_dir_proc(path, output);
        state = false;
    }
    else
    {
        log_error("\"%s\" is not a file\n", path);
    }

    scan_request_by_chunks();

    if (output)
        fclose(output);

    return state;
}

bool scanner_scan(char *host, char *port, char *session, char *format, char *path, char *file)
{
    if (!file)
    {
        log_fatal("Cannot start a scan without output file");
    }
    
    scanner_set_output(file);

    log_debug("File open: %s", file);

    scanner_set_host(host);
    scanner_set_port(port);
    scanner_set_session(session);
    scanner_set_format(format);
    return scanner_recursive_scan(path);
}

int scanner_get_file_contents(char *host, char *port, char *session, char * hash, char *file)
{
    if (!file)
    {
        log_fatal("Cannot download contents without output file");
    }
   
    output = fopen(file, "w+");

    scanner_set_host(host);
    scanner_set_port(port);
    scanner_set_session(session);

    int err_code = curl_request(API_REQ_GET,hash,output);

    fclose(output);
    free(output_path);

    return err_code;
}

bool scanner_umz(char * md5)
{
    if (output == NULL)
        output = stdout;

    return curl_request(API_REQ_GET,md5,output);
}


int scanner_print_output(void)
{
    bool state = true;
    if (!output_path)
        return 1;

    output = fopen(output_path, "r");
    char c;
    
    if (output) 
    {
        while ((c = getc(output)) != EOF)
            putchar(c);
    
        fclose(output);
        state = false;
    }
    
    free(output_path);
    return state;   
}