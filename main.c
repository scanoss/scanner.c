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
#include <stdio.h>
#include <string.h>
#include <unistd.h> 
#include <stdlib.h>
#include <dirent.h>
#include <sys/stat.h>
#include "scanner.h"

int main(int argc, char *argv[])
{
    int param = 0;
    FILE * output = stdout;
    /* Command parser */
    while ((param = getopt (argc, argv, "F:H:p:f:o:l:hdt")) != -1)
        switch (param)
        {
            case 'H':
                scanner_set_host(optarg);
                break;
            case 'p':
                scanner_set_port(optarg);
                break;
            case 'f':
                scanner_set_format(optarg);
                break;
            case 'o':
                output = fopen(optarg,"w+");
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
                exit(curl_request(API_REQ_GET,optarg,output));
                break;
            case 'h':
            default:
                fprintf(stderr, "SCANOSS scanner-%s\n", VERSION);
                fprintf(stderr, "Usage: scanner FILE or scanner DIR\n");
                fprintf(stderr, "Option\t\t Meaning\n");
                fprintf(stderr, "-h\t\t Show this help\n");
                fprintf(stderr, "-f<format>\t Output format, could be: plain (default), spdx, spdx_xml or cyclonedx.\n");
                fprintf(stderr, "-o<file_name>\t Save the scan results in the specified file\n");
                fprintf(stderr, "-l<file_name>\t Set logs filename\n");
                fprintf(stderr, "-d\t\t Enable debug messages\n");
                fprintf(stderr, "-t\t\t Enable trace messages, enable to see post request to the API\n");
                fprintf(stderr, "\nFor more information, please visit https://scanoss.com\n");
                exit(EXIT_FAILURE);
            break;
        }
    
       
    char *path = argv[optind];
    
    scanner_recursive_scan(path, output);

    
	return EXIT_SUCCESS;
}
