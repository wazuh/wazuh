/*   $OSSEC, rootcheck.c, v0.1, 2005/10/08, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
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


#define ROOTCHECK_DIR    "/queue/rootcheck"

/** Global variables **/
char _rk_buf[1024];
char _rk_comment[512];
char _rk_comment2[512];


char *rk_agent_ips[MAX_AGENTS];
FILE *rk_agent_fps[MAX_AGENTS];

extern int mailq;
int rk_err;


/* SyscheckInit
 * Initialize the necessary information to process the syscheck information
 */
void RootcheckInit()
{
    int i = 0;

    rk_err = 0;
    
    for(;i<MAX_AGENTS;i++)
    {
        rk_agent_ips[i] = NULL;
        rk_agent_fps[i] = NULL;
    }

    return;
}


/* RkDB_File
 * Return the file pointer to be used
 */
FILE *RK_File(char *agent, int *agent_id)
{
    int i = 0;

    while(rk_agent_ips[i] != NULL)
    {
        if(strcmp(rk_agent_ips[i],agent) == 0)
        {
            /* pointing to the beginning of the file */
            fseek(rk_agent_fps[i],0, SEEK_SET);
            *agent_id = i;
            return(rk_agent_fps[i]);
        }
        
        i++;    
    }

    /* If here, our agent wasn't found */
    rk_agent_ips[i] = strdup(agent);

    if(rk_agent_ips[i] != NULL)
    {
        snprintf(_rk_buf,1024,"%s/%s",ROOTCHECK_DIR,agent);
        
        /* r+ to read and write. Do not truncate */
        rk_agent_fps[i] = fopen(_rk_buf,"r+");
        if(!rk_agent_fps[i])
        {
            /* try opening with a w flag, file probably does not exist */
            rk_agent_fps[i] = fopen(_rk_buf, "w");
            if(rk_agent_fps[i])
            {
                fclose(rk_agent_fps[i]);
                rk_agent_fps[i] = fopen(_rk_buf, "r+");
            }
        }
        if(!rk_agent_fps[i])
        {
            merror(FOPEN_ERROR, ARGV0,_rk_buf);
            
            free(rk_agent_ips[i]);
            rk_agent_ips[i] = NULL;

            return(NULL);
        }

        /* Returning the opened pointer (the beginning of it) */
        fseek(rk_agent_fps[i],0, SEEK_SET);
        *agent_id = i;
        return(rk_agent_fps[i]);
    }

    else
    {
        merror(MEM_ERROR,ARGV0);
        return(NULL);
    }

    return(NULL);
}


/* RK_Search
 * Search the RK DB for any entry related.
 */
void RK_Search(Eventinfo *lf)
{
    int agent_id;

    char *tmpstr;

    FILE *fp;

    fp = RK_File(lf->location, &agent_id);

    if(!fp)
    {
        merror("%s: Error handling rootcheck database",ARGV0);
        rk_err++; /* Increment rk error */

        return;
    }

    /* Reads the file and search for a possible
     * entry
     */
    while(fgets(_rk_buf, 1024, fp) != NULL)
    {
        /* Ignore blank lines and lines with a comment */
        if(_rk_buf[0] == '\n' || _rk_buf[0] == '#')
        {
            continue;
        }

        /* Removing new line */
        tmpstr = index(_rk_buf, '\n');
        if(tmpstr)
            *tmpstr = '\0';    


        /* Cannot use strncmp to avoid errors with crafted files */    
        if(strcmp(lf->log, _rk_buf) == 0)
        {
            return;
        }
    }                

    /* if we reach here, we need to alert */
    lf->comment = "Rootkit detection engine message";

    lf->level = Config.rootcheck;

    lf->sigid = ROOTCHECK_PLUGIN;


    /* Adding the new entry at the end of the file */
    fseek(fp, 0, SEEK_END);
    fprintf(fp,"%s\n",lf->log);
    fflush(fp);


    /* alert/ notify */ 
    if(Config.mailbylevel <= Config.integrity)    
        lf->mail_flag = 1;
                                
    if(Config.logbylevel <= Config.integrity)
        OS_Log(lf);

    return; 
}


/* Special decoder for rootcheck
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive
 */
void DecodeRootcheck(Eventinfo *lf)
{
    lf->type = ROOTCHECK; 
    
    RK_Search(lf);
   
    return;
}

/* EOF */
