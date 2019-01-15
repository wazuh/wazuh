/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

#include "os_regex/os_regex.h"

#define OSSECCONF   "ossec.conf"
#define OS_MAXSTR   1024

int total;


int fileexist(char *file)
{
    FILE *fp;

    /* Open file */
    fp = fopen(file, "r");
    if (!fp) {
        return (0);
    }

    fclose(fp);
    return (1);
}

int dogrep(char *file, char *str)
{
    char line[OS_MAXSTR + 1];
    FILE *fp;

    /* Open file */
    fp = fopen(file, "r");
    if (!fp) {
        return (0);
    }

    /* Clear memory */
    memset(line, '\0', OS_MAXSTR + 1);

    /* Read file and look for str */
    while (fgets(line, OS_MAXSTR, fp) != NULL) {
        if (OS_Match(str, line)) {
            fclose(fp);
            return (1);
        }
    }

    fclose(fp);
    return (0);
}

/* Check if syscheck is present in the config */
int config_file(char *name, char *file, int quiet)
{
    char ffile[256];
    FILE *fp;

    ffile[255] = '\0';

    /* Check if the file has a variable format */
    if (strchr(file, '%') != NULL) {
        time_t tm;
        struct tm *p;

        tm = time(NULL);
        p = localtime(&tm);

        if (strftime(ffile, 255, file, p) == 0) {
            return (-1);
        }
    } else {
        strncpy(ffile, file, 255);
    }

    /* Look for ffile */
    if (!fileexist(ffile)) {
        if (quiet == 0) {
            printf("%s: Log file not existent: '%s'.\n", name, file);
        }
        return (-1);
    }

    if (dogrep(OSSECCONF, file)) {
        printf("%s: Log file already configured: '%s'.\n",
               name, file);
        return (0);
    }

    /* Add IIS config */
    fp = fopen(OSSECCONF, "a");
    if (!fp) {
        printf("%s: Unable to edit configuration file.\n", name);
        return (0);
    }

    printf("%s: Adding log file to be monitored: '%s'.\n", name, file);
    fprintf(fp, "\r\n"
            "\r\n"
            "<!-- Extra log file -->\r\n"
            "<ossec_config>\r\n"
            "  <localfile>\r\n"
            "    <location>%s</location>\r\n"
            "    <log_format>syslog</log_format>\r\n"
            "  </localfile>\r\n"
            "</ossec_config>\r\n\r\n", file);

    printf("%s: Action completed.\n", name);
    fclose(fp);

    return (0);
}

/* Setup Windows after install */
int main(int argc, char **argv)
{
    int quiet = 0;

    if (argc < 2) {
        printf("%s: Invalid syntax.\n", argv[0]);
        printf("Try: '%s <file_name>'\n\n", argv[0]);
    }

    /* Look for the quiet option */
    if ((argc == 3) && (strcmp(argv[2], "--quiet") == 0)) {
        quiet = 1;
    }

    /* Check if OSSEC-HIDS was installed already */
    if (!fileexist(OSSECCONF)) {
        printf("%s: Unable to find ossec config: '%s'.\n", argv[0], OSSECCONF);
    } else {
        config_file(argv[0], argv[1], quiet);
    }

    return (0);
}
