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


#include "fts.h"
#include "eventinfo.h"

int fts_minsize_for_str = 0;
OSList *fts_list = NULL;
FILE *fp_list = NULL;
FILE *fp_ignore = NULL;


/** int FTS_Init()
 * Starts the FTS module.
 */
int FTS_Init()
{
    int fts_list_size;
    
    fts_list = OSList_Create();
    if(!fts_list)
    {
        merror(LIST_ERROR, ARGV0);
        return(0);
    }

    /* Getting default list size */
    fts_list_size = getDefine_Int("analysisd",
                                  "fts_list_size",
                                  12,512);

    /* Getting minimum string size */
    fts_minsize_for_str = getDefine_Int("analysisd",
                                        "fts_min_size_for_str",
                                        6, 128);
    
    if(!OSList_SetMaxSize(fts_list, fts_list_size))
    {
        merror(LIST_SIZE_ERROR, ARGV0);
        return(0);
    }
    if(!OSList_SetFreeDataPointer(fts_list, free))
    {
        merror(LIST_FREE_ERROR, ARGV0);
        return(0);
    }

    /* creating fts list */
    fp_list = fopen(FTS_QUEUE, "r+");
    if(!fp_list)
    {
        /* Create the file if we cant open it */
        fp_list = fopen(FTS_QUEUE, "w+");
        if(fp_list)
            fclose(fp_list);
        
        fp_list = fopen(FTS_QUEUE, "r+");
        if(!fp_list)
        {
            merror(FOPEN_ERROR, ARGV0, FTS_QUEUE);
            return(0);
        }
    }


    /* Creating ignore list */
    fp_ignore = fopen(IG_QUEUE, "r+");
    if(!fp_ignore)
    {
        /* Create the file if we cant open it */
        fp_ignore = fopen(IG_QUEUE, "w+");
        if(fp_ignore)
            fclose(fp_ignore);
        
        fp_ignore = fopen(IG_QUEUE, "r+");
        if(!fp_ignore)
        {
            merror(FOPEN_ERROR, ARGV0, IG_QUEUE);
            return(0);
        }
    }
                                                            
    return(1);
}

/* AddtoIGnore -- adds a pattern to be ignored.
 */
void AddtoIGnore(Eventinfo *lf)
{
    char _line[OS_FLSIZE + 1];

    _line[OS_FLSIZE] = '\0';

    /* Assigning the values to the FTS */
    snprintf(_line,OS_FLSIZE, "%s %s %s %s %s %s %s",
            (lf->log_tag && (lf->generated_rule->ignore & FTS_NAME))?
                        lf->log_tag:"",
            (lf->id && (lf->generated_rule->ignore & FTS_ID))?lf->id:"",
            (lf->user && (lf->generated_rule->ignore & FTS_USER))?lf->user:"",
            (lf->srcip && (lf->generated_rule->ignore & FTS_SRCIP))?
                        lf->srcip:"",
            (lf->dstip && (lf->generated_rule->ignore & FTS_DSTIP))?
                        lf->dstip:"",
            (lf->data && (lf->generated_rule->ignore & FTS_DATA))?
                        lf->data:"",            
            (lf->systemname && (lf->generated_rule->ignore & FTS_SYSTEMNAME))?
                        lf->systemname:"",            
            (lf->generated_rule->ignore & FTS_LOCATION)?lf->location:"");

    fseek(fp_ignore, 0, SEEK_END);    
    fprintf(fp_ignore,"%s\n", _line);
    fflush(fp_ignore);

    return;
}


/* IGnore v0.1
 * Check if the event is to be ignored.
 * Only after an event is matched (generated_rule must be set).
 */
int IGnore(Eventinfo *lf)
{
    char _line[OS_FLSIZE + 1];
    char _fline[OS_FLSIZE +1];

    _line[OS_FLSIZE] = '\0';


    /* Assigning the values to the FTS */
    snprintf(_line,OS_FLSIZE, "%s %s %s %s %s %s %s\n",
            (lf->log_tag && (lf->generated_rule->ckignore & FTS_NAME))?
                            lf->log_tag:"",
            (lf->id && (lf->generated_rule->ckignore & FTS_ID))?lf->id:"",
            (lf->user && (lf->generated_rule->ckignore & FTS_USER))?
                            lf->user:"",
            (lf->srcip && (lf->generated_rule->ckignore & FTS_SRCIP))?
                            lf->srcip:"",
            (lf->dstip && (lf->generated_rule->ckignore & FTS_DSTIP))?
                            lf->dstip:"",
            (lf->data && (lf->generated_rule->ignore & FTS_DATA))?
                            lf->data:"",
            (lf->systemname && (lf->generated_rule->ignore & FTS_SYSTEMNAME))?
                            lf->systemname:"",                                
            (lf->generated_rule->ckignore & FTS_LOCATION)?lf->location:"");

    _fline[OS_FLSIZE] = '\0';


    /** Checking if the ignore is present **/
    /* Pointing to the beginning of the file */
    fseek(fp_ignore, 0, SEEK_SET);
    while(fgets(_fline, OS_FLSIZE , fp_ignore) != NULL)
    {
        if(strcmp(_fline, _line) != 0)
            continue;

        /* If we match, we can return 1 */
        return(1);
    }

    return(0);
}


/* FTS v0.1
 *  Check if the word "msg" is present on the "queue".
 *  If it is not, write it there.
 */ 
int FTS(Eventinfo *lf)
{
    int msgsize;
    int number_of_matches = 0;
    int _fline_size;

    char _line[OS_FLSIZE + 1];
    char _fline[OS_FLSIZE +1];
    
    char *line_for_list;

    OSListNode *fts_node;

    _line[OS_FLSIZE] = '\0';

    /* Assigning the values to the FTS */
    snprintf(_line,OS_FLSIZE, "%s %s %s %s %s %s %s %s",
            (lf->log_tag && (lf->fts & FTS_NAME))?lf->log_tag:"",
            (lf->id && (lf->fts & FTS_ID))?lf->id:"",
            (lf->user && (lf->fts & FTS_USER))?lf->user:"",
            (lf->dstuser && (lf->fts & FTS_DSTUSER))?lf->dstuser:"",
            (lf->srcip && (lf->fts & FTS_SRCIP))?lf->srcip:"",
            (lf->dstip && (lf->fts & FTS_DSTIP))?lf->dstip:"",
            (lf->data && (lf->fts & FTS_DATA))?lf->data:"",
            (lf->systemname && (lf->fts & FTS_SYSTEMNAME))?lf->systemname:"",
            (lf->fts & FTS_LOCATION)?lf->location:"");


    /* Getting the msgsize size */
    msgsize = strlen(_line);


    /* Maximum size is OS_FLSIZE */
    if(msgsize >= OS_FLSIZE)
    {
        merror(SIZE_ERROR, ARGV0, _line);
        return(0);
    }

    _fline[OS_FLSIZE] = '\0';
    

    /** Checking if FTS is already present **/
    /* Pointing to the beginning of the file */
    fseek(fp_list, 0, SEEK_SET);
    while(fgets(_fline, OS_FLSIZE , fp_list) != NULL)
    {
        _fline_size = strlen(_fline) -1;

        if(strncmp(_fline, _line, _fline_size) != 0)
            continue;

        /* If we match, we can return 0 and keep going */
        return(0);
    }

    /* Checking if from the last FTS events, we had
     * at least 3 "similars" before. If yes, we just
     * ignore it.
     */
    fts_node = OSList_GetLastNode(fts_list);
    while(fts_node)
    {
        if(OS_StrHowClosedMatch((char *)fts_node->data, _line) > 
                fts_minsize_for_str)
        {
            number_of_matches++;

            /* We go and add this new entry to the list */
            if(number_of_matches > 2)
            {
                _line[fts_minsize_for_str] = '\0';
                break;
            }
        }

        fts_node = OSList_GetPrevNode(fts_list);
    }

    os_strdup(_line, line_for_list);
    OSList_AddData(fts_list, line_for_list);


    /* Rule has not being fired */	
    fprintf(fp_list,"%s\n", _line);
    fflush(fp_list);

    return(1);
}


/* EOF */
