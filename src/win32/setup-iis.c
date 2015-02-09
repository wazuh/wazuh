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

int total;


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

/* Get Windows directory */
static void get_win_dir(char *file, int f_size)
{
    ExpandEnvironmentStrings("%WINDIR%", file, f_size);

    if (!direxist(file)) {
        strncpy(file, "C:\\WINDOWS", f_size);
    }
}

int config_dir(char *name, char *dir, char *vfile)
{
    FILE *fp;

    if (!direxist(dir)) {
        return (0);
    }

    if (dogrep(OSSECCONF, vfile)) {
        printf("%s: Log file already configured: '%s'.\n",
               name, vfile);
        return (1);
    }

    printf("%s: IIS directory found, but no valid log.\n", name);
    printf("%s: You may have it configured in a format different\n"
           "               than W3C Extended or you just don't have today's\n"
           "               log available.\n", name);
    printf("%s: http://www.ossec.net/en/manual.html#iis\n\n", name);

    /* Add IIS config */
    fp = fopen(OSSECCONF, "a");
    if (!fp) {
        printf("%s: Unable to edit configuration file.\n", name);
        return (1);
    }

    fprintf(fp, "\r\n"
            "\r\n"
            "<!-- IIS log file -->\r\n"
            "<ossec_config>\r\n"
            "  <localfile>\r\n"
            "    <location>%s</location>\r\n"
            "    <log_format>iis</log_format>\r\n"
            "  </localfile>\r\n"
            "</ossec_config>\r\n\r\n", vfile);

    printf("%s: Action completed.\n", name);

    total++;
    fclose(fp);

    return (1);
}

/* Check if the IIS file is present in the config */
int config_iis(char *name, char *file, char *vfile)
{
    FILE *fp;

    if (!fileexist(file)) {
        return (0);
    }

    total++;

    if (dogrep(OSSECCONF, vfile)) {
        printf("%s: Log file already configured: '%s'.\n",
               name, vfile);
        return (1);
    }

    printf("%s: Adding IIS log file to be monitored: '%s'.\n", name, vfile);

    /* Add iis config config */
    fp = fopen(OSSECCONF, "a");
    if (!fp) {
        printf("%s: Unable to edit configuration file.\n", name);
        return (1);
    }

    fprintf(fp, "\r\n"
            "\r\n"
            "<!-- IIS log file -->\r\n"
            "<ossec_config>\r\n"
            "  <localfile>\r\n"
            "    <location>%s</location>\r\n"
            "    <log_format>iis</log_format>\r\n"
            "  </localfile>\r\n"
            "</ossec_config>\r\n\r\n", vfile);

    printf("%s: Action completed.\n", name);
    fclose(fp);

    return (1);
}

/* Setup Windows after install */
int main(int argc, char **argv)
{
    int i = 0;
    time_t tm;
    struct tm *p;
    char win_dir[2048];

    if (argc >= 2) {
        if (chdir(argv[1]) != 0) {
            printf("%s: Invalid directory: '%s'.\n", argv[0], argv[1]);
            return (0);
        }
    }

    /* Check if ossec was installed already */
    if (!fileexist(OSSECCONF)) {
        printf("%s: Unable to find ossec config: '%s'", argv[0], OSSECCONF);
        exit(0);
    }

    /* Get today's day */
    tm = time(NULL);
    p = localtime(&tm);

    total = 0;

    printf("%s: Looking for IIS log files to monitor.\r\n",
           argv[0]);
    printf("%s: For more information: http://www.ossec.net/en/win.html\r\n",
           argv[0]);
    printf("\r\n");

    /* Get Window directory */
    get_win_dir(win_dir, sizeof(win_dir) - 1);

    /* Look for IIS log files */
    while (i <= 254) {
        char lfile[OS_MAXSTR + 1];
        char vfile[OS_MAXSTR + 1];

        i++;

        /* Search for NCSA */
        snprintf(lfile,
                 OS_MAXSTR,
                 "%s\\System32\\LogFiles\\W3SVC%d\\nc%02d%02d%02d.log",
                 win_dir, i, (p->tm_year + 1900) - 2000, p->tm_mon + 1, p->tm_mday);
        snprintf(vfile,
                 OS_MAXSTR,
                 "%s\\System32\\LogFiles\\W3SVC%d\\nc%%y%%m%%d.log",
                 win_dir, i);

        /* Try dir-based */
        config_iis(argv[0], lfile, vfile);

        /* Search for W3C extended */
        snprintf(lfile,
                 OS_MAXSTR,
                 "%s\\System32\\LogFiles\\W3SVC%d\\ex%02d%02d%02d.log",
                 win_dir, i, (p->tm_year + 1900) - 2000, p->tm_mon + 1, p->tm_mday);

        snprintf(vfile,
                 OS_MAXSTR,
                 "%s\\System32\\LogFiles\\W3SVC%d\\ex%%y%%m%%d.log",
                 win_dir, i);

        /* Try dir-based */
        if (config_iis(argv[0], lfile, vfile) == 0) {
            snprintf(lfile,
                     OS_MAXSTR,
                     "%s\\System32\\LogFiles\\W3SVC%d", win_dir, i);
            config_dir(argv[0], lfile, vfile);
        }

        /* Search for FTP Extended format */
        snprintf(lfile,
                 OS_MAXSTR,
                 "%s\\System32\\LogFiles\\MSFTPSVC%d\\ex%02d%02d%02d.log",
                 win_dir, i, (p->tm_year + 1900) - 2000, p->tm_mon + 1, p->tm_mday);

        snprintf(vfile,
                 OS_MAXSTR,
                 "%s\\System32\\LogFiles\\MSFTPSVC%d\\ex%%y%%m%%d.log",
                 win_dir, i);
        if (config_iis(argv[0], lfile, vfile) == 0) {
            snprintf(lfile,
                     OS_MAXSTR,
                     "%s\\System32\\LogFiles\\MSFTPSVC%d", win_dir, i);
            config_dir(argv[0], lfile, vfile);
        }

        /* Search for IIS SMTP logs */
        snprintf(lfile,
                 OS_MAXSTR,
                 "%s\\System32\\LogFiles\\SMTPSVC%d\\ex%02d%02d%02d.log",
                 win_dir, i, (p->tm_year + 1900) - 2000, p->tm_mon + 1, p->tm_mday);

        snprintf(vfile,
                 OS_MAXSTR,
                 "%s\\System32\\LogFiles\\SMTPSVC%d\\ex%%y%%m%%d.log",
                 win_dir, i);
        if (config_iis(argv[0], lfile, vfile) == 0) {
            snprintf(lfile,
                     OS_MAXSTR,
                     "%s\\System32\\LogFiles\\SMTPSVC%d", win_dir, i);
            config_dir(argv[0], lfile, vfile);
        }
    }

    if (total == 0) {
        printf("%s: No IIS log added. Look at the link above for more "
               "information.\r\n", argv[0]);
    }

    return (0);
}
