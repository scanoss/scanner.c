// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/scanner.h
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



#ifndef __SCANNER_H
#define __SCANNER_H

#include <stdio.h>
#include <stdbool.h>

#define VERSION "1.2.3"
#define MAX_HEADER_LEN 1024 * 1024 * 1024 * 10
#define MAX_FILE_SIZE (1024 * 1024 * 4)
#define MIN_FILE_SIZE 128

#define SCAN_STATUS_MAX_SIZE 512


enum 
{
    API_REQ_GET,
    API_REQ_POST
};

typedef enum
{
    SCANNER_STATE_OK = 0,
    SCANNER_STATE_INIT,
    SCANNER_STATE_WFP_CALC,
    SCANNER_STATE_ANALIZING,
    SCANNER_STATE_FORMATING,
    SCANNER_STATE_ERROR
} scanner_state_t;

#define MAX_COMPONENT_SIZE 128
typedef struct scanner_status_t
{
    unsigned int id;
    char API_host[32];
    char API_port[5];
    char API_session[33];
    char format[16];
    char component_last[MAX_COMPONENT_SIZE];
    char * scan_path;
    char *output_path;
    char *wfp_path;
    FILE *output;
    unsigned int files_chunk_size;
    unsigned int wfp_files;
    unsigned int scanned_files;
    long wfp_total_time;
    long last_chunk_response_time;
    long total_response_time;
    char message[SCAN_STATUS_MAX_SIZE];
    scanner_state_t state;    
} scanner_status_t;

#define API_HOST_DEFAULT "osskb.org/api"
#define API_PORT_DEFAULT "443"
#define API_SESSION_DEFAULT "\0"
#define DEFAULT_FILES_CHUNK 100

#define __SCANNER_STATUS_INIT {.API_host = API_HOST_DEFAULT, .API_port = API_PORT_DEFAULT, .API_session = API_SESSION_DEFAULT, .format = "plain", .files_chunk_size = DEFAULT_FILES_CHUNK}

void scanner_set_log_level(int level);
void scanner_set_verbose(bool in);
void scanner_set_buffer_size(unsigned int size);
void scanner_set_format(scanner_status_t *s, char * form);
void scanner_set_host(scanner_status_t *s, char * host);
void scanner_set_port(scanner_status_t *s, char * port);
void scanner_set_session(scanner_status_t *s, char *session);
void scanner_set_output(scanner_status_t *s, char * f);
int scanner_print_output(scanner_status_t *scanner);
void scanner_set_log_file(char *log);
scanner_status_t * scanner_create(unsigned int id, char * host, char * port, char * session, char * format, char * path, char * file);
int scanner_recursive_scan(scanner_status_t *scanner);
bool scanner_umz(char * md5);
int scanner_get_file_contents(scanner_status_t *scanner, char * hash);
void scanner_free(scanner_status_t * scanner);
#endif
