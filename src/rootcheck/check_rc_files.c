/*   $OSSEC, check_rc_files.c, v0.1, 2005/09/30, Daniel B. Cid$   */

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
#include <errno.h>

#include "headers/defs.h"
#include "headers/debug_op.h"

#include "rootcheck.h"



/* check_rc_files:
 * Read the file pointer specified (rootkit_files)
 * and check if the configured file is there
 */
void check_rc_files(char *basedir, FILE *fp)
{
    char buf[OS_MAXSTR +1];
    char file_path[OS_MAXSTR +1];

    char *file;
    char *name;
    char *link;
   
    int _errors = 0;
    int _total = 0;
     
     
    debug1("%s: DEBUG: Starting on check_rc_files", ARGV0);
     
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
        name = nbuf; 
         
         
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
               if(*nbuf == ' ' || *nbuf == '\t')
               {
                   nbuf++;
                   name = nbuf;

                   break;
               }
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

        
        /* Getting the link (if present) */
        link = index(nbuf, ':');
        if(link)
        {
            *link = '\0';
           
            link++; 
            if(*link == ':')
            {
                link++;
            }
        }
       
         
        /* Cleaning any space of \t at the end */
        nbuf = index(nbuf, ' ');
        if(nbuf)
        {
            *nbuf = '\0';
        }

        nbuf = index(nbuf, '\t');
        if(nbuf)
        {
            *nbuf = '\0';
        }
        
        snprintf(file_path, OS_MAXSTR, "%s/%s",basedir, file);

        _total++;
        
        /* Checking if file exists */        
        if(is_file(file_path))
        {
            char op_msg[OS_MAXSTR +1];
            
            _errors = 1;
            snprintf(op_msg, OS_MAXSTR, "Rootkit '%s' detected "
                     "by the presence of file '%s'.",name, file_path);
            
            notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
        }
        
        newline:
            continue;        
    }

    if(_errors == 0)
    {
        char op_msg[OS_MAXSTR +1];
        snprintf(op_msg, OS_MAXSTR, "No presence of public rootkits detected."
                                    " Analized %d files.", _total);
        notify_rk(ALERT_OK, op_msg);
    }
}


/* EOF */
