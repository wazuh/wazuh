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
#include "os_regex/os_regex.h"

#define OSSECCONF   "ossec.conf"
#define OSSECDEF    "default-ossec.conf"
#define CLIENTKEYS  "client.keys"
#define OS_MAXSTR   1024

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
int config_syscheck()
{
    FILE *fp;
    if(dogrep(OSSECCONF, "syscheck"))
    {
        return(0);
    }
    
    /* Add syscheck config */
    fp = fopen(OSSECCONF, "a");
    if(!fp)
        return(0); 
   
    fprintf(fp, "%s\r\n", 
    "\r\n"    
    "<!-- Default syscheck config -->\r\n"
    "<ossec_config>\r\n"
    "  <syscheck>\r\n"
    "    <frequency>7200</frequency>\r\n"
    "    <directories check_all=\"yes\">C:\\WINDOWS,C:\\Program Files</directories>\r\n"

    "    <ignore>C:\\WINDOWS\\Internet Logs</ignore>\r\n"
    "  </syscheck>\r\n"
    "</ossec_config>\r\n");

    fclose(fp);

    return(0);
                    
}

/* Setup windows after install */
int main(int argc, char **argv)
{
    if(argc < 2)
    {
        printf("%s: Invalid syntax.\n", argv[0]);
        printf("Try: '%s directory'\n\n", argv[0]);
        return(0);
    }
    
    if(chdir(argv[1]) != 0)
    {
        printf("%s: Invalid directory: '%s'.\n", argv[0], argv[1]);
        return(0);
    }
    
    /* Checking if ossec was installed already */
    if(!fileexist(OSSECCONF))
    {
        char cmd[OS_MAXSTR +1];
        
        /* Copy default config to ossec.conf */
        snprintf(cmd, OS_MAXSTR, "copy %s %s", OSSECDEF, OSSECCONF);
        system(cmd);

        /* Run iis-logs */
        snprintf(cmd, OS_MAXSTR, "iis-logs.bat");
        system(cmd);
                        
        /* Run manage agents */
        snprintf(cmd, OS_MAXSTR, "manage_agents.exe");
        system(cmd);
    }

    /* If it is present, we need to do the upgrade */
    else
    {
        /* Look if syscheck is configured, if not, do so */
        config_syscheck();

        /* Call manage-agents if not key */
        if(!fileexist(CLIENTKEYS))
        {
            /* Run manage agents */
            char cmd[OS_MAXSTR +1];

            snprintf(cmd, OS_MAXSTR, "manage_agents.exe");
            system(cmd);
        }
    }

    return(0);
}
