/* @(#) $Id$ */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
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

    /* Opening file */
    fp = fopen(file, "r");
    if(!fp)
        return(0);

    fclose(fp);
    return(1);
}

int dogrep(char *file, char *str)
{
    char line[OS_MAXSTR +1];
    FILE *fp;

    /* Opening file */
    fp = fopen(file, "r");
    if(!fp)
        return(0);

    /* Clearing memory */
    memset(line, '\0', OS_MAXSTR +1);

    /* Reading file and looking for str */ 
    while(fgets(line, OS_MAXSTR, fp) != NULL)
    {
        if(OS_Match(str, line))
        {
            fclose(fp);
            return(1);
        }
    }

    fclose(fp);
    return(0);
}



/* Check is syscheck is present in the config */
int config_iis(char *name, char *file)
{
    int add = 0;
    FILE *fp;

    if(!fileexist(file))
    {
        return(0);
    }

    total++;

    if(dogrep(OSSECCONF, file))
    {
        printf("%s: Log file already configured: '%s'.\n", 
                name, file);
        return(0);
    }

    printf("%s: Adding IIS log file to be monitored: '%s'.\n", name,file);
    printf("%s: Continue? (y/n):", name);
    while(1)
    {
        char u_buffer[256];
        memset(u_buffer, '\0', 256);
        if((fgets(u_buffer, 254, stdin) != NULL) &&
                (strlen(u_buffer) < 250))
        {
            if((u_buffer[0] == 'y') || (u_buffer[0] == 'Y'))
            {
                add = 1;
                break;
            }
            else if((u_buffer[0] == 'n') || (u_buffer[0] == 'N'))
            {
                add = 0;
                break;
            }
        }
    }

    if(add == 0)
    {
        printf("%s: Action not taken.\n", name);
        return(0);
    }


    /* Add iis config config */
    fp = fopen(OSSECCONF, "a");
    if(!fp)
    {
        printf("%s: Unable to edit configuration file.\n", name);
        return(0); 
    }

    fprintf(fp, "\r\n" 
            "\r\n"    
            "<!-- IIS log file -->\r\n"
            "<ossec_config>\r\n"
            "  <localfile>\r\n"
            "    <location>%s</location>"
            "    <log_format>iis</log_format>\r\n"
            "  </localfile>\r\n"
            "</ossec_config>\r\n\r\n", file);

    printf("%s: Action completed.\n", name);
    fclose(fp);

    return(0);

}

/* Setup windows after install */
int main(int argc, char **argv)
{
    int i = 0;

    time_t tm;
    struct tm *p;
        
    
    if(argc >= 2)
    {
        if(chdir(argv[1]) != 0)
        {
            printf("%s: Invalid directory: '%s'.\n", argv[0], argv[1]);
            return(0);
        }
    }
    
    /* Checking if ossec was installed already */
    if(!fileexist(OSSECCONF))
    {
        printf("%s: Unable to find ossec config: '%s'", argv[0], OSSECCONF);
        exit(0);
    }

    /* Getting todays day */
    tm = time(NULL);
    p = localtime(&tm);
        
    total = 0;    

    printf("%s: Looking for IIS log files to monitor.\r\n", 
                argv[0]);
    printf("%s: For more information: http://www.ossec.net/en/win.html\r\n", 
                argv[0]);
    printf("\r\n");
    
    
    /* Looking for IIS log files */
    while(i <= 254)
    {
        char lfile[OS_MAXSTR +1];

        i++;

        /* Searching for NCSA */
        snprintf(lfile, 
                OS_MAXSTR, 
                "C:\\WINDOWS\\System32\\LogFiles\\W3SVC%d\\nc%02d%02d%02d.log",
                i, (p->tm_year+1900)-2000, p->tm_mon+1, p->tm_mday);
    
        config_iis(argv[0], lfile);


        /* Searching for W3C extended */
        snprintf(lfile, 
                OS_MAXSTR, 
                "C:\\WINDOWS\\System32\\LogFiles\\W3SVC%d\\ex%02d%02d%02d.log",
                i, (p->tm_year+1900)-2000, p->tm_mon+1, p->tm_mday);
    
        config_iis(argv[0], lfile);


        /* Searching for FTP Extended format */
        snprintf(lfile, 
             OS_MAXSTR, 
             "C:\\WINDOWS\\System32\\LogFiles\\MSFTPSVC%d\\ex%02d%02d%02d.log",
             i, (p->tm_year+1900)-2000, p->tm_mon+1, p->tm_mday);
    
        config_iis(argv[0], lfile);
    }

    if(total == 0)
    {
        printf("%s: No IIS log found. Look at the link above for more "
               "information.\r\n", argv[0]);
    }
    system("pause");
    
    return(0);
}
