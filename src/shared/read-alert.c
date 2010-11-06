/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


/* File monitoring functions */

#include "shared.h"
#include "read-alert.h"


/* ** Alert xyz: email active-response ** */

#define ALERT_BEGIN     "** Alert"
#define ALERT_BEGIN_SZ  8
#define RULE_BEGIN      "Rule: "
#define RULE_BEGIN_SZ   6
#define SRCIP_BEGIN     "Src IP: "
#define SRCIP_BEGIN_SZ  8
#define SRCPORT_BEGIN     "Src Port: "
#define SRCPORT_BEGIN_SZ  10
#define DSTIP_BEGIN     "Dst IP: "
#define DSTIP_BEGIN_SZ  8
#define DSTPORT_BEGIN     "Dst Port: "
#define DSTPORT_BEGIN_SZ  10
#define USER_BEGIN      "User: "
#define USER_BEGIN_SZ   6
#define ALERT_MAIL      "mail"
#define ALERT_MAIL_SZ   4
#define ALERT_AR        "active-response"


/** void FreeAlertData(alert_data *al_data)
 * Free alert data.
 */
void FreeAlertData(alert_data *al_data)
{
    if(al_data->date)
    {
        free(al_data->date);
    }
    if(al_data->location)
    {
        free(al_data->location);
    }
    if(al_data->comment)
    {
        free(al_data->comment);
    }
    if(al_data->group)
    {
        free(al_data->group);
    }
    if(al_data->srcip)
    {
        free(al_data->srcip);
    }
    if(al_data->user)
    {
        free(al_data->user);
    }
    if(al_data->log)
    {
        while(*(al_data->log))
        {
            free(*(al_data->log));
            al_data->log++;
        }
    }
    free(al_data);
    al_data = NULL;
}


/** alert_data *GetAlertData(FILE *fp)
 * Returns alert data for the file specified
 */
alert_data *GetAlertData(int flag, FILE *fp)
{
    int _r = 0, log_size;
    char *p;

    char *date = NULL;
    char *comment = NULL;
    char *location = NULL;
    char *srcip = NULL;
    char *dstip = NULL;
    char *user = NULL;
    char *group = NULL;
    char **log = NULL;
    int level, rule, srcport, dstport;
    
    char str[OS_BUFFER_SIZE+1];
    str[OS_BUFFER_SIZE]='\0';


    while(fgets(str, OS_BUFFER_SIZE, fp) != NULL)
    {
        
        /* Enf of alert */
        if(strcmp(str, "\n") == 0 && log_size > 0)
        {
            /* Found in here */
            if(_r == 2)
            {
                alert_data *al_data;
                os_calloc(1, sizeof(alert_data), al_data);
                al_data->level = level;
                al_data->rule = rule;
                al_data->location = location;
                al_data->comment = comment;
                al_data->group = group;
                al_data->log = log;
                al_data->srcip = srcip;
                al_data->srcport = srcport;
                al_data->dstip = dstip;
                al_data->dstport = dstport;
                al_data->user = user;
                al_data->date = date;
               
                return(al_data);
            }
            _r = 0;
        }
        
        
        /* Checking for the header */
        if(strncmp(ALERT_BEGIN, str, ALERT_BEGIN_SZ) == 0)
        {
            p = str + ALERT_BEGIN_SZ + 1;
            
            /* Searching for email flag */
            p = strchr(p, ' ');
            if(!p)
            {
                continue;
            }

            p++;
        
        
            /* Checking for the flags */    
            if((flag & CRALERT_MAIL_SET) && 
               (strncmp(ALERT_MAIL, p, ALERT_MAIL_SZ) != 0))
            {
                continue;
            }

            p = strchr(p, '-');
            if(p)
            {
                p++;
                os_strdup(p, group);

                /* Cleaning new line from group */
                os_clearnl(group, p);
            }


            /* Searching for active-response flag */
            _r = 1;
            continue;
        }

        if(_r < 1)
            continue;
            
            
        /*** Extract information from the event ***/
        
        /* r1 means: 2006 Apr 13 16:15:17 /var/log/auth.log */
        if(_r == 1)
        {
            /* Clear new line */
            os_clearnl(str, p);
             
            p = strchr(str, ':');
            if(p)
            {
                p = strchr(p, ' ');
                if(p)
                {
                    *p = '\0';
                    p++;
                }
                else
                {
                    /* If p is null it is because strchr failed */
                    merror("ZZZ: 1() Merror date or location not NULL");
                    _r = 0;
                    goto l_error;
                }
            }


            /* If not, str is date and p is the location */
            if(date || location)
                merror("ZZZ Merror date or location not NULL");
            
            os_strdup(str, date);
            os_strdup(p, location);    
            _r = 2;
            log_size = 0;
            continue;
        }

        
        else if(_r == 2)
        {
            /* Rule begin */
            if(strncmp(RULE_BEGIN, str, RULE_BEGIN_SZ) == 0)
            {
                os_clearnl(str,p);
                
                p = str + RULE_BEGIN_SZ;
                rule = atoi(p);

                p = strchr(p, ' ');
                if(p)
                {
                    p++;
                    p = strchr(p, ' ');
                    if(p)
                        p++;
                }

                if(!p)
                    goto l_error;
                
                level = atoi(p);
                
                /* Getting the comment */
                p = strchr(p, '\'');
                if(!p)
                    goto l_error;
                
                p++;
                os_strdup(p, comment);
                
                /* Must have the closing \' */
                p = strrchr(comment, '\'');
                if(p)
                {
                    *p = '\0';
                }
                else
                {
                    goto l_error;
                }
            }
            
            /* srcip */
            else if(strncmp(SRCIP_BEGIN, str, SRCIP_BEGIN_SZ) == 0)
            {
                os_clearnl(str,p);
                
                p = str + SRCIP_BEGIN_SZ;
                os_strdup(p, srcip);
            }
            /* srcport */
            else if(strncmp(SRCPORT_BEGIN, str, SRCPORT_BEGIN_SZ) == 0)
            {
                os_clearnl(str,p);
                
                p = str + SRCPORT_BEGIN_SZ;
                srcport = atoi(p);
            }
            /* dstip */
            else if(strncmp(DSTIP_BEGIN, str, DSTIP_BEGIN_SZ) == 0)
            {
                os_clearnl(str,p);
                
                p = str + DSTIP_BEGIN_SZ;
                os_strdup(p, dstip);
            }
            /* dstport */
            else if(strncmp(DSTPORT_BEGIN, str, DSTPORT_BEGIN_SZ) == 0)
            {
                os_clearnl(str,p);
                
                p = str + DSTPORT_BEGIN_SZ;
                dstport = atoi(p);
            }
            /* username */
            else if(strncmp(USER_BEGIN, str, USER_BEGIN_SZ) == 0)
            {
                os_clearnl(str,p);
                
                p = str + USER_BEGIN_SZ;
                os_strdup(p, user);
            }
            /* It is a log message */
            else if(log_size < 20)
            {
                os_clearnl(str,p);
                
                os_realloc(log, (log_size +2)*sizeof(char *), log);
                os_strdup(str, log[log_size]); 
                log_size++;
                log[log_size] = NULL;
            }
        }

        continue;
        l_error:
        
        /* Freeing the memory */
        _r = 0;
        if(date)
        {
            free(date);
            date = NULL;
        }
        if(location)
        {
            free(location);
            location = NULL;
        }
        if(comment)
        {
            free(comment);
            comment = NULL;
        }
        if(srcip)
        {
            free(srcip);
            srcip = NULL;
        }
        if(user)
        {
            free(user);
            user = NULL;
        }
        if(group)
        {
            free(group);
            group = NULL;
        }
        while(log_size > 0)
        {
            log_size--;
            if(log[log_size])
            {
                free(log[log_size]);
                log[log_size] = NULL;
            }
        }
    }

    /* We need to clean end of file before returning */
    clearerr(fp);
    return(NULL);
}


/* EOF */
