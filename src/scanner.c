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
#define API_HOST_DEFAULT "osskb.org"
#define API_PORT_DEFAULT "443"
#define API_SESSION_DEFAULT "\0"

#define WFP_SCAN_FILE_NAME "scan.wfp"

const char EXCLUDED_DIR[] = ".git, .svn, .eggs, __pycache__, node_modules, vendor,";
const char EXCLUDED_EXTENSIONS[] = ".png, .html, .xml, .svg, .yaml, .yml, .txt, .json, .gif, .md,"
                                   ".test, .cfg, .pdf, .properties, .jpg, .vim, .sql, .result, .template,"
                                   ".tiff, .bmp, .DS_Store, .eot, .otf, .ttf, .woff, .rgb, .conf, .whl, .o, .ico, .wfp,";

static char API_host[32] = API_HOST_DEFAULT;
static char API_port[5] = API_PORT_DEFAULT;
static char API_session[33] = API_SESSION_DEFAULT;

static char format[10] = "plain";
static unsigned int proc_files = 0;

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

static void wfp_capture(char *root, char *path, char *wfp_buffer)
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

    char *file_name = path + strlen(root);

    /* Save file information to buffer */
    sprintf(wfp_buffer + strlen(wfp_buffer), "file=%s,%lu,%s\n", hex_md5, length, file_name + 1);
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
static bool scanner_file_proc(char *root, char *path, FILE *output)
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

    wfp_capture(root, path, wfp_buffer);
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

int api_curl_post(char *host, char *port, char *session, char *version, char *format, char *wfp, FILE *output)
{

    char body_template[] = "--------------------------scanoss_wfp_scan\r\n"
                           "Content-Disposition: form-data; name=\"format\"\r\n\r\n%s\r\n"
                           "--------------------------scanoss_wfp_scan--\r\n"
                           "Content-Disposition: form-data; name=\"file\"; filename=\"scan.wfp\"\r\n"
                           "Content-Type: application/octet-stream\r\n"
                           "\r\n%s\r\n"
                           "--------------------------scanoss_wfp_scan--\r\n\r\n";

    char user_version[64];
    char user_session[64];
    long m_port = strtol(port, NULL, 10);

    sprintf(user_session, "X-session: %s", session);
    sprintf(user_version, "User-Agent: SCANOSS_scanner.c/%s", version);

    log_debug("Version:%s", user_version);

    char *http_request = calloc(strlen(wfp) + strlen(body_template) + 100, 1);
    sprintf(http_request, body_template, format, wfp);
    log_trace(http_request);

    free(wfp);

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
        curl_easy_setopt(curl, CURLOPT_URL, "osskb.org/api/scan/direct");
        curl_easy_setopt(curl, CURLOPT_PORT, m_port);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, http_request);

        if (log_level_is_enabled(LOG_TRACE))
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

        curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

        struct curl_slist *chunk = NULL;
        chunk = curl_slist_append(chunk, "Connection: close");
        chunk = curl_slist_append(chunk, user_version);
        chunk = curl_slist_append(chunk, user_session);
        chunk = curl_slist_append(chunk, "Content-Type: multipart/form-data; boundary=------------------------scanoss_wfp_scan");
        chunk = curl_slist_append(chunk, "Expect:");
        chunk = curl_slist_append(chunk, "Accept: */*");

        res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

        curl_easy_setopt(curl, CURLOPT_WRITEDATA, output);

        /* Perform the request, res will get the return code */
        res = curl_easy_perform(curl);
        /* Check for errors */
        if (res != CURLE_OK)
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));

        /* always cleanup */
        curl_easy_cleanup(curl);
    }

    curl_global_cleanup();
    free(http_request);
    return 0;
}

static bool api_request(FILE *output)
{

    long buffer_size = 0;
    char *wfp_buffer = read_file(WFP_SCAN_FILE_NAME, &buffer_size);
    wfp_buffer[buffer_size] = 0;
    bool state = true;
    if (*wfp_buffer)
    {
        api_curl_post(API_host, API_port, API_session, VERSION, format, wfp_buffer, output);
        state = false;
    }

    return state;
}

/* Scan all files from a Directory*/
static bool scanner_dir_proc(char *root, char *path, FILE *output)
{

    bool state = true; //true if were a error

    DIR *d = opendir(path);
    if (d == NULL)
        return false;
    struct dirent *entry; // for the directory entries

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
            scanner_dir_proc(root, temp, output); //If its a valid directory, then process it
        }
        else if (scanner_is_file(temp))
        {
            if (!scanner_file_proc(root, temp, output))
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

/********* PUBLIC FUNTIONS DEFINITION ************/

void scanner_set_format(char *form)
{
    if (strstr(form, "plain") || strstr(form, "spdx") || strstr(form, "cyclonedx"))
        strncpy(format, form, sizeof(format));
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

bool scanner_recursive_scan(char *path, FILE *output)
{
    bool state = true;
    log_debug("Scan start");
    proc_files = 0;

    /*create blank wfp file*/
    FILE *wfp_f = fopen(WFP_SCAN_FILE_NAME, "w+");
    fclose(wfp_f);

    if (scanner_is_file(path))
    {
        scanner_file_proc("", path, output);
        state = false;
    }
    else if (scanner_is_dir(path))
    {
        int path_len = strlen(path);
        if (path_len > 1 && path[path_len - 1] == '/') //remove extra '/'
            path[path_len - 1] = '\0';

        scanner_dir_proc(path, path, output);
        state = false;
    }
    else
    {
        log_error("\"%s\" is not a file\n", path);
    }

    api_request(output);

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
    FILE *output;

    output = fopen(file, "w+");
    log_debug("File open: %s", file);

    scanner_set_host(host);
    scanner_set_port(port);
    scanner_set_session(session);
    scanner_set_format(format);

    return scanner_recursive_scan(path, output);
}