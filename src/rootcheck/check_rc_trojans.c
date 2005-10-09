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
                goto newline;
            else
                break;
        }

        if(*nbuf == '\0')
            goto newline;

        /* File now may be valid */
        file = nbuf;
        string_to_look = nbuf; 


        /* Getting the file and the rootkit name */
        while(*nbuf != '\0')
        {
            if(*nbuf == ' ' || *nbuf == '\t')
            {
                /* Setting the limit for the file */
                *nbuf = '\0';
                nbuf++;
                break;
            }
            else
            {
                nbuf++;
            }
        }

        if(*nbuf == '\0')
            goto newline;


        /* Some ugly code to remove spaces and \t */ 
        while(*nbuf != '\0')
        {
            if(*nbuf == '!')
            {
                nbuf++;
                string_to_look = nbuf;
                break;
            }
            else if(*nbuf == ' ' || *nbuf == '\t')
            {
                nbuf++;
                continue;
            }
            else
            {
                goto newline;
            }
        }


        if(!string_to_look)
        {
            goto newline;
        }


        /* Removing any possible space of \t at the end */
        nbuf = index(string_to_look, ' ');
        if(nbuf)
        {
            *nbuf = '\0';
        }

        nbuf = index(string_to_look, '\t');
        if(nbuf)
        {
            *nbuf = '\0';
        }

        _total++;
        
        /* Trying with all possible paths */
        for(i = 0;i<=3;i++)
        {
            snprintf(file_path, OS_MAXSTR, "%s/%s/%s",basedir, 
                    all_paths[i],
                    file);

            if(is_file(file_path) && os_string(file_path, string_to_look))
            {
                char op_msg[OS_MAXSTR +1];
                _errors = 1;
            
                snprintf(op_msg, OS_MAXSTR, "Trojaned version of file "
                        "'%s' detected. Signature used: '%s'", 
                                        file_path,
                                        string_to_look);

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
                                    "Analized %d files", _total);
        notify_rk(ALERT_OK, op_msg);
    }
}


/* EOF */
