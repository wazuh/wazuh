/* @(#) $Id: ./src/analysisd/decoders/rootcheck.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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
#include "decoder.h"


#define ROOTCHECK_DIR    "/queue/rootcheck"


/** Global variables **/
char *rk_agent_ips[MAX_AGENTS];
FILE *rk_agent_fps[MAX_AGENTS];

int rk_err;

/* Rootcheck decoder */
OSDecoderInfo *rootcheck_dec = NULL;


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


    /* Zeroing decoder */
    os_calloc(1, sizeof(OSDecoderInfo), rootcheck_dec);
    rootcheck_dec->id = getDecoderfromlist(ROOTCHECK_MOD);
    rootcheck_dec->type = OSSEC_RL;
    rootcheck_dec->name = ROOTCHECK_MOD;
    rootcheck_dec->fts = 0;

    debug1("%s: RootcheckInit completed.", ARGV0);

    return;
}


/* RK_File
 * Return the file pointer to be used
 */
FILE *RK_File(char *agent, int *agent_id)
{
    int i = 0;
    char rk_buf[OS_SIZE_1024 +1];

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
        snprintf(rk_buf,OS_SIZE_1024, "%s/%s", ROOTCHECK_DIR,agent);

        /* r+ to read and write. Do not truncate */
        rk_agent_fps[i] = fopen(rk_buf,"r+");
        if(!rk_agent_fps[i])
        {
            /* try opening with a w flag, file probably does not exist */
            rk_agent_fps[i] = fopen(rk_buf, "w");
            if(rk_agent_fps[i])
            {
                fclose(rk_agent_fps[i]);
                rk_agent_fps[i] = fopen(rk_buf, "r+");
            }
        }
        if(!rk_agent_fps[i])
        {
            merror(FOPEN_ERROR, ARGV0, rk_buf, errno, strerror(errno));

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
        merror(MEM_ERROR,ARGV0, errno, strerror(errno));
        return(NULL);
    }

    return(NULL);
}


/* Special decoder for rootcheck
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive
 */
int DecodeRootcheck(Eventinfo *lf)
{
    int agent_id;

    char *tmpstr;
    char rk_buf[OS_SIZE_2048 +1];

    FILE *fp;

    fpos_t fp_pos;

    /* Zeroing rk_buf */
    rk_buf[0] = '\0';
    rk_buf[OS_SIZE_2048] = '\0';

    fp = RK_File(lf->location, &agent_id);

    if(!fp)
    {
        merror("%s: Error handling rootcheck database.",ARGV0);
        rk_err++; /* Increment rk error */

        return(0);
    }

    /* Getting initial position */
    if(fgetpos(fp, &fp_pos) == -1)
    {
        merror("%s: Error handling rootcheck database (fgetpos).",ARGV0);
        return(0);
    }


    /* Reads the file and search for a possible
     * entry
     */
    while(fgets(rk_buf, OS_SIZE_2048 -1, fp) != NULL)
    {
        /* Ignore blank lines and lines with a comment */
        if(rk_buf[0] == '\n' || rk_buf[0] == '#')
        {
            if(fgetpos(fp, &fp_pos) == -1)
            {
                merror("%s: Error handling rootcheck database "
                       "(fgetpos2).",ARGV0);
                return(0);
            }
            continue;
        }

        /* Removing new line */
        tmpstr = strchr(rk_buf, '\n');
        if(tmpstr)
        {
            *tmpstr = '\0';
        }


        /* Old format without the time stampts */
        if(rk_buf[0] != '!')
        {
            /* Cannot use strncmp to avoid errors with crafted files */
            if(strcmp(lf->log, rk_buf) == 0)
            {
                rootcheck_dec->fts = 0;
                lf->decoder_info = rootcheck_dec;
                return(1);
            }
        }
        /* New format */
        else
        {
            /* Going past time: !1183431603!1183431603  (last, first saw) */
            tmpstr = rk_buf + 23;

            /* Matches, we need to upgrade last time saw */
            if(strcmp(lf->log, tmpstr) == 0)
            {
                fsetpos(fp, &fp_pos);
                fprintf(fp, "!%d", lf->time);
                rootcheck_dec->fts = 0;
                lf->decoder_info = rootcheck_dec;
                return(1);
            }
        }

        /* Getting current position */
        if(fgetpos(fp, &fp_pos) == -1)
        {
            merror("%s: Error handling rootcheck database (fgetpos3).",ARGV0);
            return(0);
        }
    }


    /* Adding the new entry at the end of the file */
    fseek(fp, 0, SEEK_END);
    fprintf(fp,"!%d!%d %s\n",lf->time, lf->time, lf->log);
    fflush(fp);

    rootcheck_dec->fts = 0;
    rootcheck_dec->fts |= FTS_DONE;
    lf->decoder_info = rootcheck_dec;
    return(1);
}


/* EOF */
