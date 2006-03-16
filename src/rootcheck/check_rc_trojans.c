/*   $OSSEC, check_rc_trojans.c, v0.1, 2005/10/01, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include <stdio.h>       
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <sys/param.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rootcheck.h"


/* check_rc_trojans:
 * Read the file pointer specified (rootkit_trojans)
 * and check if the any trojan entry is on the configured files
 */
void check_rc_trojans(char *basedir, FILE *fp)
{
    int i, _errors = 0, _total = 0;
    char buf[OS_MAXSTR +1];
    char file_path[OS_MAXSTR +1];

    char *file;
    char *string_to_look;

    char *(all_paths[]) = {"bin","sbin","usr/bin","usr/sbin"};


    debug1("%s: DEBUG: Starting on check_rc_trojans", ARGV0);


    while(fgets(buf, OS_MAXSTR, fp) != NULL)
    {
        char *nbuf;
        char *message = NULL;

        /* Removing end of line */
        nbuf = index(buf, '\n');
        if(nbuf)
        {
            *nbuf = '\0';
        }

        /* Assigning buf to be used */
        nbuf = buf;

        /* Excluding commented lines or blanked ones */ 
        while(*nbuf != '\0')
        {
            if(*nbuf == ' ' || *nbuf == '\t')
            {
                nbuf++;
                continue;
            }
            else if(*nbuf == '#')
            {
                *nbuf = '\0';
                break;
            }
            else
                break;
        }

        if(*nbuf == '\0')
            continue;


        /* File now may be valid */
        file = nbuf;
        string_to_look = nbuf; 

        string_to_look = strchr(file, '!');
        if(!string_to_look)
        {
            goto newline;
        }
        
        *string_to_look = '\0';
        string_to_look++;
        
        /* Cleaning the file */
        while(*file != '\0')
        {
            if(*file != ' ' && *file != '\t')
                break;
            file++;    
        }

        /* Cleaning spaces */
        nbuf = strchr(file, ' ');
        if(nbuf)
            *nbuf = '\0';
        nbuf = strchr(file, '\t');
        if(nbuf)
            *nbuf = '\0';
        
                
        /* Cleaning the string to look */
        while(*string_to_look != '\0')
        {
            if(*string_to_look != ' ' && *string_to_look != '\t')
                break;
            string_to_look++;
        }
        
        /* Cleaning spaces */
        nbuf = strchr(string_to_look, '!');
        if(nbuf)
        {
            *nbuf = '\0';
            nbuf++;
        }
        else
        {
            goto newline;    
        }
        
        /* Getting any possible message */
        message = nbuf;
        
        /* Cleaning the message */
        while(*message != '\0')
        {
            if(*message != ' ' && *message != '\t')
                break;
            message++;    
        }
                                                                                    
        if(!string_to_look)
        {
            goto newline;
        }


        _total++;
        
        /* Trying with all possible paths */
        for(i = 0;i<=3;i++)
        {
            if(*file != '/')
            {
                snprintf(file_path, OS_MAXSTR, "%s/%s/%s",basedir, 
                        all_paths[i],
                        file);
            }
            else
            {
                strncpy(file_path, file, OS_MAXSTR);
                file_path[OS_MAXSTR -1] = '\0';
                i = 4;
            }
            
            if(is_file(file_path) && os_string(file_path, string_to_look))
            {
                char op_msg[OS_MAXSTR +1];
                _errors = 1;
            
                snprintf(op_msg, OS_MAXSTR, "Trojaned version of file "
                        "'%s' detected. Signature used: '%s' (%s)", 
                                        file_path,
                                        string_to_look,
                                        *message == '\0'?"Trojan":message);

                notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
            }
        }

    newline:
        continue;        
    }


    if(_errors == 0)
    {
        char op_msg[OS_MAXSTR +1];
        snprintf(op_msg, OS_MAXSTR, "No binaries with any trojan detected. "
                                    "Analyzed %d files", _total);
        notify_rk(ALERT_OK, op_msg);
    }
}


/* EOF */
