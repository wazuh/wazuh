/* Copyright (C) 2009 Trend Micro Inc.
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
#include <sys/types.h>
#include <dirent.h>
#include <time.h>
#include <windows.h>

#include "os_regex/os_regex.h"

#define OSSECCONF   "ossec.conf"
#define OS_MAXSTR   1024


/* Check if a file exists */
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

/* Grep for a string in a file */
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

/* Check if dir exists */
int direxist(char *dir)
{
    DIR *dp;

    /* Open dir */
    dp = opendir(dir);
    if (dp == NULL) {
        return (0);
    }

    closedir(dp);
    return (1);
}

/* Get Windows main directory */
void get_win_dir(char *file, int f_size)
{
    ExpandEnvironmentStrings("%WINDIR%", file, f_size);

    if (!direxist(file)) {
        strncpy(file, "C:\\WINDOWS", f_size);
    }
}
