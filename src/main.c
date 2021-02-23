// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * src/main.c
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

#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include "scanner.h"

void scanner_evt(const scanner_status_t * p_scanner, scanner_evt_t evt)
{
    printf("Scanner EVT: %d\r\n", evt);
}

int main(int argc, char *argv[])
{
    int param = 0;
    bool print_output = true;
    char * file = NULL;
    char format[20] = "plain";
    char host[32] = API_HOST_DEFAULT;
    char port[5] = API_PORT_DEFAULT;
    char session[64] = API_SESSION_DEFAULT;
    char path[512];

    while ((param = getopt (argc, argv, "F:H:p:f:o:l:hdt")) != -1)
        switch (param)
        {
            case 'H':
                strcpy(host,optarg);
                break;
            case 'p':
                strcpy(port,optarg);
                break;
            case 'f':
                strcpy(format,optarg);
                break;
            case 'o':
                asprintf(&file,"%s",optarg);
                print_output = false;
                break;
            case 'l':
                scanner_set_log_file(optarg);
            case 'd':
                scanner_set_log_level(1);
                break;
            case 't':
                scanner_set_log_level(0);
                break;
            case 'F':
                exit(scanner_umz(optarg));
                break;
            case 'h':
            default:
                fprintf(stderr, "SCANOSS scanner-%s\n", VERSION);
                fprintf(stderr, "Usage: scanner FILE or scanner DIR\n");
                fprintf(stderr, "Option\t\t Meaning\n");
                fprintf(stderr, "-h\t\t Show this help\n");
                fprintf(stderr, "-f<format>\t Output format, could be: plain (default), spdx, spdx_xml or cyclonedx.\n");
                fprintf(stderr, "-F<md5>\t UMZ a MD5 hash\n");
                fprintf(stderr, "-o<file_name>\t Save the scan results in the specified file\n");
                fprintf(stderr, "-l<file_name>\t Set logs filename\n");
                fprintf(stderr, "-d\t\t Enable debug messages\n");
                fprintf(stderr, "-t\t\t Enable trace messages, enable to see post request to the API\n");
                fprintf(stderr, "\nFor more information, please visit https://scanoss.com\n");
                exit(EXIT_FAILURE);
            break;
        }
    
       
    strcpy(path,argv[optind]);
    char id[MAX_ID_LEN];
    sprintf(id,"scanoss CLI,%u", rand());
    scanner_object_t * scanner = scanner_create(id, host,port,session,format,path,file, scanner_evt);
    scanner_recursive_scan(scanner);
    
    if (print_output)
        scanner_print_output(scanner);

    scanner_object_free(scanner);
	
    return EXIT_SUCCESS;
}
