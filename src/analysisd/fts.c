/*   $OSSEC, fts.c, v0.2, 2005/02/15, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* First time seen functions 
 */


#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "error_messages/error_messages.h"

#include "headers/defs.h"
#include "headers/file_op.h"
#include "headers/debug_op.h"
#include "os_regex/os_regex.h"

#include "fts.h"
#include "eventinfo.h"
#include "rules.h"

char *snort_fts_comment = "First time this snort rule was fired";

/* _Internal_FTS v0.1
 *  Check if the word "msg" is present on the file "queue".
 *  If it is not, write it there.
 */ 
int _Internal_FTS(char *queue, Eventinfo *lf)
{
    FILE *fp;
    int msgsize;
    char _line[OS_FLSIZE + 1];

    _line[OS_FLSIZE] = '\0';

   
    /* If lf->fts is not set, return */
    if(!lf->fts)
        return(0);
        
         
    /* Assigning the values to the FTS */
    snprintf(_line,OS_FLSIZE -1, "%s %s %s %s %s %s %s",
                                 (lf->fts & FTS_NAME)?lf->log_tag:"",
                                 (lf->fts & FTS_ID)?lf->id:"",
                                 (lf->fts & FTS_USER)?lf->user:"",
                                 (lf->fts & FTS_DSTUSER)?lf->dstuser:"",
                                 (lf->fts & FTS_SRCIP)?lf->srcip:"",
                                 (lf->fts & FTS_DSTIP)?lf->dstip:"",
                                 (lf->fts & FTS_LOCATION)?lf->location:"");
                                  

    /* Getting the msgsize size */
    msgsize = strlen(_line);

   
    /* If File_Date of char <= is because the file is not present */ 
    if(File_DateofChange(queue) >= 0)
    {
        char _fline[OS_FLSIZE +1];
        
        _fline[OS_FLSIZE] = '\0';

        
        fp = fopen(queue, "r");
        if(!fp)
        {
            merror("int-fts: Unable to open the fts queue for read");
            return(-1);
        }

        /* Checking this FTS is already present */
        while(fgets(_fline, OS_FLSIZE , fp) != NULL)
        {
            if(strlen(_fline) >= OS_FLSIZE)
            {
                merror("int-fts: Line overflow. Log problem.");
                return(-1);
            }
            
            if(strlen(_fline) != (msgsize + 1))
                continue;
                
            if(strncmp(_fline, _line, msgsize) != 0)
                continue;

            fclose(fp);

            /* If we match, we can return 0 and keep going */
            return(0);
        }
        
        /* Close here to open latter */
        fclose(fp);
    }

    
    /* Rule has not being fired or queue is not present */	
    fp = fopen(queue, "a");
    if(!fp)
    {
        merror("int-fts: Unable to open the fts queue to write.");
        return(-1);
    }
    
    fprintf(fp,"%s\n", _line);
    
    fclose(fp);
    return(1);
}


/* FTS will check if the log is compatible with the syslog
 * FTS analysis. If it is, it will check if this is the first entry
 * for the received log.
 */
int FTS(Eventinfo *lf)
{
    if(_Internal_FTS(SYSLOG_FTS_QUEUE,lf))
    {
        lf->sigid = FTS_PLUGIN;
        return(1);
    }

    return(0);	
}


/* Run the FTS for all snort events */
int Snort_FTS(Eventinfo *lf)
{

    if(_Internal_FTS(SNORT_FTS_QUEUE,lf))
    {
        lf->sigid = SNORT_FTS_PLUGIN;
        lf->comment = snort_fts_comment;
        return(1);
    }

    return(0);
}
