/* @(#) $Id$ */

/* Copyright (C) 2006-2007 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


/* Hostinfo decoder */


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
int hi_err = 0;
int id_new = 0;
int id_mod = 0;
char _hi_buf[OS_MAXSTR +1];


/* Agent hash */
OSHash *agent_hash = NULL;


/* Hostinfo decoder */
OSDecoderInfo *hostinfo_dec = NULL;



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


    /* Zeroing decoder */
    os_calloc(1, sizeof(OSDecoderInfo), hostinfo_dec);
    hostinfo_dec->id = getDecoderfromlist(HOSTINFO_MOD);
    hostinfo_dec->type = OSSEC_RL;
    hostinfo_dec->name = HOSTINFO_MOD;
    hostinfo_dec->fts = 0;
    id_new = getDecoderfromlist(HOSTINFO_NEW);
    id_mod = getDecoderfromlist(HOSTINFO_MOD);

    
    /* clearing the buffer */
    memset(_hi_buf, '\0', OS_MAXSTR +1);


    /* Creating agent hash */
    agent_hash = OSHash_Create();
    if(!agent_hash)
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }

    
    return;
}



/* HI_File
 * Return the file pointer to be used
 */
FILE *HI_File(char *agent)
{
    FILE *fp;
    char *agent_pt = NULL;

    fp = OSHash_Get(agent_hash, agent);
    if(fp)
    {
        fseek(fp, 0, SEEK_SET);
        return(fp);
    }


    /* If here, our agent wasn't found */
    agent_pt = strdup(agent);

    if(agent_pt != NULL)
    {
        char hi_buf[OS_SIZE_1024 +1];
        snprintf(hi_buf,OS_SIZE_1024, "%s/%s", HOSTINFO_DIR, agent);

        /* r+ to read and write. Do not truncate */
        fp = fopen(hi_buf,"r+");
        if(!fp)
        {
            /* try opening with a w flag, file probably does not exist */
            fp = fopen(hi_buf, "w");
            if(fp)
            {
                fclose(fp);
                fp = fopen(hi_buf, "r+");
            }
        }
        if(!fp)
        {
            merror(FOPEN_ERROR, ARGV0, hi_buf);

            free(agent_pt);
            return(NULL);
        }


        /* Adding to the hash */
        OSHash_Add(agent_hash, agent_pt, fp);


        /* Returning the opened pointer (the beginning of it) */
        fseek(fp, 0, SEEK_SET);
        return(fp);
    }

    else
    {
        merror(MEM_ERROR, ARGV0);
        return(NULL);
    }

    return(NULL);
}



/* Special decoder for Hostinformation
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive.
 */
int DecodeHostinfo(Eventinfo *lf)
{
    int changed = 0;
    int bf_size;
    
    char *ip;
    char *portss;
    char *tmpstr;

    char buffer[OS_MAXSTR + 1];
    char opened[OS_MAXSTR + 1];
    FILE *fp;

    
    /* Checking maximum number of errors */
    if(hi_err > 10)
        return(0);
                

    /* Zeroing buffers */
    buffer[OS_MAXSTR] = '\0';
    opened[OS_MAXSTR] = '\0';
    fp = HI_File(lf->location);
    if(!fp)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++; /* Increment hi error */

        return(0);
    }


    /* Copying log to buffer */
    strncpy(buffer,lf->log, OS_MAXSTR);
    
    
    /* Getting ip */
    tmpstr = __go_after(buffer, HOST_HOST);
    if(!tmpstr)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++;

        return(0);
    }

    
    /* Setting ip */
    ip = tmpstr;
    tmpstr = strchr(tmpstr, ',');
    if(!tmpstr)
    {
        merror("%s: Error handling host information database.",ARGV0);
        hi_err++;

        return(0);
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
                return(0);
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


    /* Setting decoder */
    lf->decoder_info = hostinfo_dec;

    
    /* Setting comment */
    if(changed == 1)
    {
        hostinfo_dec->id = id_mod;
        //lf->generated_rule->last_events[0] = opened;
    }
    else
    {
        hostinfo_dec->id = id_new;
    }
    

    return(1);
}



/* EOF */
