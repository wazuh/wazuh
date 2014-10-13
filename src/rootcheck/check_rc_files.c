/* @(#) $Id: ./src/rootcheck/check_rc_files.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "rootcheck.h"



/* check_rc_files:
 * Read the file pointer specified (rootkit_files)
 * and check if the configured file is there
 */
void check_rc_files(const char *basedir, FILE *fp)
{
    char buf[OS_SIZE_1024 +1];
    char file_path[OS_SIZE_1024 +1];

    char *file;
    char *name;
    char *link;

    int _errors = 0;
    int _total = 0;


    debug1("%s: DEBUG: Starting on check_rc_files", ARGV0);

    while(fgets(buf, OS_SIZE_1024, fp) != NULL)
    {
        char *nbuf;

        /* Removing end of line */
        nbuf = strchr(buf, '\n');
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
        link = strchr(nbuf, ':');
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
        nbuf = strchr(nbuf, ' ');
        if(nbuf)
        {
            *nbuf = '\0';

            nbuf = strchr(nbuf, '\t');
            if(nbuf)
            {
                *nbuf = '\0';
            }
        }

        _total++;


        /* Checking if it is a file to search everywhere */
        if(*file == '*')
        {
            if(rk_sys_count >= MAX_RK_SYS)
            {
                merror(MAX_RK_MSG, ARGV0, MAX_RK_SYS);
            }

            else
            {
                /* Removing * / from the file */
                file++;
                if(*file == '/')
                    file++;

                /* Memory assignment */
                rk_sys_file[rk_sys_count] = strdup(file);
                rk_sys_name[rk_sys_count] = strdup(name);

                if(!rk_sys_name[rk_sys_count] ||
                   !rk_sys_file[rk_sys_count] )
                {
                    merror(MEM_ERROR, ARGV0);

                    if(rk_sys_file[rk_sys_count])
                        free(rk_sys_file[rk_sys_count]);
                    if(rk_sys_name[rk_sys_count])
                        free(rk_sys_name[rk_sys_count]);

                    rk_sys_file[rk_sys_count] = NULL;
                    rk_sys_name[rk_sys_count] = NULL;
                }

                rk_sys_count++;

                /* Always assigning the last as NULL */
                rk_sys_file[rk_sys_count] = NULL;
                rk_sys_name[rk_sys_count] = NULL;
            }
            continue;
        }

        snprintf(file_path, OS_SIZE_1024, "%s/%s",basedir, file);

        /* Checking if file exists */
        if(is_file(file_path))
        {
            char op_msg[OS_SIZE_1024 +1];

            _errors = 1;
            snprintf(op_msg, OS_SIZE_1024, "Rootkit '%s' detected "
                     "by the presence of file '%s'.",name, file_path);

            notify_rk(ALERT_ROOTKIT_FOUND, op_msg);
        }

        newline:
            continue;
    }

    if(_errors == 0)
    {
        char op_msg[OS_SIZE_1024 +1];
        snprintf(op_msg,OS_SIZE_1024,"No presence of public rootkits detected."
                                    " Analyzed %d files.", _total);
        notify_rk(ALERT_OK, op_msg);
    }
}


/* EOF */
