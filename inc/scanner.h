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

#define VERSION "1.2.2"
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

typedef struct scanner_status_t
{
    unsigned int id;
    unsigned int wfp_files;
    unsigned int scanned_files;
    long wfp_total_time;
    long last_chunk_response_time;
    long total_response_time;
    char message[SCAN_STATUS_MAX_SIZE];
    scanner_state_t state;    
} scanner_status_t;

void scanner_set_log_level(int level);
void scanner_set_verbose(bool in);
void scanner_set_buffer_size(unsigned int size);
void scanner_set_format(char * form);
void scanner_set_host(char * host);
void scanner_set_port(char * port);
void scanner_set_session(char *session);
void scanner_set_output(char * f);
int scanner_print_output(void);
void scanner_set_log_file(char *log);
bool scanner_recursive_scan(char * path);
bool scanner_umz(char * md5);
int scanner_scan(char * host, char * port, char * session, char * format, char * path, char * file, scanner_status_t * scanner_status);
int scanner_get_file_contents(char *host, char *port, char *session, char * hash, char *file);
scanner_status_t * scanner_get_status(void);
#endif
