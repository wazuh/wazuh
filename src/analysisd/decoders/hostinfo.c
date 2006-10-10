/* @(#) $Id$ */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Rootcheck decoder */


#include "config.h"
#include "os_regex/os_regex.h"
#include "eventinfo.h"
#include "alerts/alerts.h"


#define HOSTINFO_DIR    "/queue/fts/hostinfo"
#define HOST_HOST       "Host: "
#define HOST_PORT       " open ports: "

#define HOST_CHANGED    "Host information changed."
#define HOST_NEW        "New host information added."
#define PREV_OPEN       "Previously"


/** Global variables **/
char _hi_buf[OS_MAXSTR +1];
FILE *_hi_fp = NULL;


int hi_err;

/* Hostinformation rule */
RuleInfo *hostinfo_rule;


/* Check if the string matches.
 */
static char *__go_after(char *x, char *y)
{
    int x_s;
    int y_s;

    /* X and Y must be not null */
    if(!x || !y)
        return(NULL);

    x_s = strlen(x);
    y_s = strlen(y);

    if(x_s <= y_s)
    {
        return(NULL);
    }

    /* String does not match */
    if(strncmp(x,y,y_s) != 0)
    {
        return(NULL);
    }

    x+=y_s;

    return(x);
}



/* HostinfoInit
 * Initialize the necessary information to process the host information
 */
void HostinfoInit()
{
    hi_err = 0;
    
    /* clearing the buffer */
    memset(_hi_buf, '\0', OS_MAXSTR +1);

    /* Creating rule for Host information alerts */
    hostinfo_rule = zerorulemember(
                             HOSTINFO_PLUGIN,  /* id */ 
                             Config.hostinfo , /* level */
                             0,0,0,0,0);

    if(!hostinfo_rule)
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }
    hostinfo_rule->group = "hostinfo,";
 
 
    _hi_fp = fopen(HOSTINFO_DIR, "r+");
    if(!_hi_fp)
    {
        _hi_fp = fopen(HOSTINFO_DIR, "w");
        if(_hi_fp)
        {
            fclose(_hi_fp);
            _hi_fp = fopen(HOSTINFO_DIR, "r+");
        }

       if(!_hi_fp)
       {
           merror(FOPEN_ERROR, ARGV0, HOSTINFO_DIR);
       } 
    }
    return;
}


/* HI_File
 * Return the file pointer to be used
 */
FILE *HI_File()
{
    if(!_hi_fp)
        return(NULL);
    
    /* pointing to the beginning of the file */
    fseek(_hi_fp, 0, SEEK_SET);
    return(_hi_fp);
}


/* HI_Search
 * Search the HI DB for any entry related.
 */
void HI_Search(Eventinfo *lf)
{
    int changed = 0;
    int bf_size;
    
    char *ip;
    char *portss;
    char *tmpstr;

    char buffer[OS_MAXSTR + 1];
    char opened[OS_MAXSTR + 1];
    FILE *fp;

    buffer[OS_MAXSTR] = '\0';
    opened[OS_MAXSTR] = '\0';
    fp = HI_File();

    if(!fp)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++; /* Increment hi error */

        return;
    }

    /* Copying log to buffer */
    strncpy(buffer,lf->log, OS_MAXSTR);
    
    
    /* Getting ip */
    tmpstr = __go_after(buffer, HOST_HOST);
    if(!tmpstr)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++;

        return;
    }

    
    /* Setting ip */
    ip = tmpstr;
    tmpstr = strchr(tmpstr, ',');
    if(!tmpstr)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++;

        return;
    }
    *tmpstr = '\0';
    tmpstr++;
    portss = tmpstr;


    /* Getting ip only information -- to store */
    tmpstr = strchr(ip, ' ');
    if(tmpstr)
    {
        *tmpstr = '\0';
    }

    bf_size = strlen(ip);
    
    
    /* Reads the file and search for a possible
     * entry
     */
    while(fgets(_hi_buf, OS_MAXSTR -1, fp) != NULL)
    {
        /* Ignore blank lines and lines with a comment */
        if(_hi_buf[0] == '\n' || _hi_buf[0] == '#')
        {
            continue;
        }

        /* Removing new line */
        tmpstr = strchr(_hi_buf, '\n');
        if(tmpstr)
            *tmpstr = '\0';    


        /* Checking for ip */
        if(strncmp(ip, _hi_buf, bf_size) == 0)
        {
            /* Cannot use strncmp to avoid errors with crafted files */    
            if(strcmp(portss, _hi_buf + bf_size) == 0)
            {
                return;
            }
            else
            {
                char *tmp_ports;

                tmp_ports = _hi_buf + (bf_size +1);
                snprintf(opened, OS_MAXSTR, "%s %s", PREV_OPEN, tmp_ports);
                changed = 1;
            }
        }
    }                

    
    /* Adding the new entry at the end of the file */
    fseek(fp, 0, SEEK_END);
    fprintf(fp,"%s%s\n", ip, portss);

    /* Setting rule */
    lf->generated_rule = hostinfo_rule;
    
    /* Setting comment */
    if(changed == 1)
    {
        lf->generated_rule->comment = HOST_CHANGED;
        lf->generated_rule->last_events[0] = opened;
    }
    else
    {
        lf->generated_rule->comment = HOST_NEW;
    }
    
    OS_Log(lf);


    /* Removing pointer to hostinfo_rule */
    lf->generated_rule = NULL;
    hostinfo_rule->last_events[0] = NULL;

    return; 
}


/* Special decoder for Hostinformation 
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive.
 */
void DecodeHostinfo(Eventinfo *lf)
{
    lf->type = HOST_INFO; 

    /* Too many errors */
    if(hi_err > 10)
        return;
 
    if(hostinfo_rule->alert_opts & DO_LOGALERT)
        HI_Search(lf);
   
    return;
}

/* EOF */
