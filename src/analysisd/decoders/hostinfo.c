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


/** Global variables **/
char _hi_buf[OS_MAXSTR +1];
FILE *_hi_fp = NULL;


extern int mailq;
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

    merror("XXX starting hostingo");
    
    /* Creating rule for rootcheck alerts */
    hostinfo_rule = zerorulemember(
                             HOSTINFO_PLUGIN,  /* id */ 
                             Config.hostinfo , /* level */
                             0,0,0,0,0);

    if(!hostinfo_rule)
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }
 
 
    /* Comment */
    hostinfo_rule->comment = "System host information.";
    
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
    char *port;
    char *ip;
    char *buffer;
    char *tmpstr;

    FILE *fp;

    merror("a");
    fp = HI_File();

    merror("b");
    if(!fp)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++; /* Increment hi error */

        return;
    }

    
    /* Getting ip */
    buffer = __go_after(lf->log, HOST_HOST);
    if(!buffer)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++;

        return;
    }

    
    /* Setting ip */
    ip = buffer;
    buffer = strchr(buffer, ',');
    if(!buffer)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++;

        return;
    }
    buffer++;

    
    /* Removing port information */
    buffer = __go_after(buffer, HOST_PORT);
    if(!buffer)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++;

        return;
    }
    port = buffer;
    
    
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


        /* Cannot use strncmp to avoid errors with crafted files */    
        if(strcmp(lf->log, _hi_buf) == 0)
        {
            return;
        }
    }                

    lf->generated_rule = hostinfo_rule;
    
    
    /* Adding the new entry at the end of the file */
    fseek(fp, 0, SEEK_END);
    fprintf(fp,"%s\n",lf->log);

    OS_Log(lf);


    /* Removing pointer to rootcheck_rule */
    lf->generated_rule = NULL;

    return; 
}


/* Special decoder for Hostinformation 
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive.
 */
void DecodeHostinfo(Eventinfo *lf)
{
    lf->type = HOST_INFO; 
 
    merror("decoding: %s", lf->log);   
    if(hostinfo_rule->alert_opts & DO_LOGALERT)
        HI_Search(lf);
   
    return;
}

/* EOF */
