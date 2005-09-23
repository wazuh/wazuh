/*   $OSSEC, syscheck.c, v0.1, 2005/07/19, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* Syscheck decoder */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "headers/debug_op.h"
#include "os_regex/os_regex.h"
#include "config.h"
#include "rules.h"
#include "eventinfo.h"
#include "alerts/alerts.h"

#include "error_messages/error_messages.h"

#define SYSCHECK_DIR    "/queue/syscheck"

/** Global variables **/
char _db_buf[1024];
char _db_comment[512];
char _db_comment2[512];

/* Max limit of 256 agents */
#define MAX_AGENTS  256

char *agent_ips[MAX_AGENTS];
FILE *agent_fps[MAX_AGENTS];

int  agent_ign_num[MAX_AGENTS][66];
char *agent_ign[MAX_AGENTS][66];

extern int mailq;
int db_err;


/* File search variables */
fpos_t __initi_pos;


/* SyscheckUpdateDaily
 * Clear unnecessary events from the queue
 */
void SyscheckUpdateDaily()
{
    int i = 0;
    int j;
    
    for(;i<MAX_AGENTS;i++)
    {
        if(!agent_ips[i])
            return;
        
        for(j = 0;j<=65;j++)
        {
            if(!agent_ign[i][j])
                break;
       
            /* Chance to get back on track :) */ 
            if(agent_ign_num[i][j] > 4)    
            {
                agent_ign_num[i][j]--;
            }

        }
            
    }
}


/* SyscheckInit
 * Initialize the necessary information to process the syscheck information
 */
void SyscheckInit()
{
    int i = 0;

    db_err = 0;
    
    for(;i<MAX_AGENTS;i++)
    {
        int j;
        agent_ips[i] = NULL;
        agent_fps[i] = NULL;

        for(j = 0;j<=65;j++)
        {
            agent_ign_num[i][j] = 0;
            agent_ign[i][j] = NULL;
        }
    }

    return;
}


/* DB_File
 * Return the file pointer to be used to verify the integrity
 */
FILE *DB_File(char *agent, int *agent_id)
{
    int i = 0;

    while(agent_ips[i] != NULL)
    {
        if(strcmp(agent_ips[i],agent) == 0)
        {
            /* pointing to tbe beginning of the file */
            fseek(agent_fps[i],0, SEEK_SET);
            *agent_id = i;
            return(agent_fps[i]);
        }
        
        i++;    
    }

    /* If here, our agent wasn't found */
    agent_ips[i] = strdup(agent);

    if(agent_ips[i] != NULL)
    {
        snprintf(_db_buf,1024,"%s/%s",SYSCHECK_DIR,agent);
        
        /* r+ to read and write. Do not truncate */
        agent_fps[i] = fopen(_db_buf,"r+");
        if(!agent_fps[i])
        {
            /* try opening with a w flag, file probably does not exist */
            agent_fps[i] = fopen(_db_buf, "w");
            if(agent_fps[i])
            {
                fclose(agent_fps[i]);
                agent_fps[i] = fopen(_db_buf, "r+");
            }
        }
        if(!agent_fps[i])
        {
            merror("%s: Impossible to open '%s'",ARGV0,_db_buf);
            
            free(agent_ips[i]);
            agent_ips[i] = NULL;

            return(NULL);
        }

        /* Returning the opened pointer (the beginning of it) */
        fseek(agent_fps[i],0, SEEK_SET);
        *agent_id = i;
        return(agent_fps[i]);
    }

    else
    {
        merror(MEM_ERROR,ARGV0);
        return(NULL);
    }

    return(NULL);
}


/* DB_Search
 * Search the DB for any entry related to the file being received
 */
void DB_Search(char *f_name, char *c_sum, Eventinfo *lf)
{
    int sn_size;
    int agent_id;
    char *saved_sum;
    char *saved_name;
    FILE *fp;

    fp = DB_File(lf->location, &agent_id);
    
    if(!fp)
    {
        merror("%s: Error handling integrity database",ARGV0);
        db_err++; /* Increment db error */
    }

    /* Reads the integrity file and search for a possible
     * entry
     */
    if(fgetpos(fp, &__initi_pos) == -1)
    {
        merror("%s: Error handling integrity database (fgetpos)",ARGV0);
        return;
    }
    
    while(fgets(_db_buf, 1024, fp) != NULL)
    {
        /* Ignore blank lines and lines with a comment */
        if(_db_buf[0] == '\n' || _db_buf[0] == '#')
        {
            fgetpos(fp, &__initi_pos); /* getting next location */
            continue;
        }
            
        saved_name = index(_db_buf,' ');
        if(saved_name == NULL)
        {
            merror("%s: Invalid integrity message in the database",ARGV0);
            fgetpos(fp, &__initi_pos); /* getting next location */
            continue;
        }

        saved_name++;

        /* Removing the \n from saved_name */
        sn_size = strlen(saved_name);
        sn_size-=1; /* 0 = \0, -1 = \n */
        if(saved_name[sn_size] == '\n')
            saved_name[sn_size] = '\0';
        
        /* Cannot use strncmp to avoid errors with crafted files */    
        if(strcmp(f_name,saved_name) == 0)
        {
            char **agent_tmp = agent_ign[agent_id];
            int p = 0;
            
            saved_name--;
            *saved_name = '\0';

            saved_sum = _db_buf;

            /* checksum match, we can just return and keep going */
            if(strcmp(saved_sum,c_sum) == 0)
                return;

            /* If we reached here, the checksum of the file has changed */
            
            /* Checking how often this file has been changed and ignoring it */    
            while(*agent_tmp)
            {
                if(p >= 64)
                {
                    agent_tmp = agent_ign[agent_id];
                    if(*agent_tmp)
                    {
                        p = 0;
                        free(*agent_tmp);
                        *agent_tmp = NULL;
                        agent_ign_num[agent_id][p] = 0;
                    }
                    break;
                }
                if(strcmp(*agent_tmp,f_name) == 0)
                {
                    agent_ign_num[agent_id][p]++;
                    break;
                }

                p++;
                
            }
            
            if(*agent_tmp == NULL)
            {
                *agent_tmp = strdup(f_name);
                if(*agent_tmp == NULL)
                {
                    ErrorExit(MEM_ERROR,ARGV0);
                }
            }
            
            
            /* Checking the number of changes */
            if(agent_ign_num[agent_id][p] >= 2)
            {
                if(agent_ign_num[agent_id][p] >= 3)
                {
                    if(agent_ign_num[agent_id][p] >= 4)
                    {
                        /* Ignoring it.. */
                        return;
                    }
                    
                    /* Third change */
                    snprintf(_db_comment,512,"Integrity checksum of file '%s'"
                             " has changed again (third time). Ignoring it.",
                             f_name);
                }
                else
                {
                    /* Second change */
                    snprintf(_db_comment,512,"Integrity checksum of file '%s'"
                                             " has changed again (2nd time)",
                                             f_name);   
                }
                
            }
           
            /* First change */ 
            else
            {
                snprintf(_db_comment,512,"Integrity checksum of file '%s' "
                        "has changed.",f_name);
            }
            
            snprintf(_db_comment2,512,"Integrity checksum changed for: '%s'\n"
                                      "Old checksum was: '%s'\n"
                                      "New checksum is : '%s'\n",
                                      f_name, saved_sum, c_sum);
            
            lf->comment = _db_comment; 

            lf->level = Config.integrity;

            lf->sigid = SYSCHECK_PLUGIN;

            /* Commenting the file entry and adding a new one latter */
            fsetpos(fp, &__initi_pos);
            fputc('#',fp);

            
            /* Adding the new entry at the end of the file */
            fseek(fp, 0, SEEK_END);
            fprintf(fp,"%s %s\n",c_sum,f_name);
           
            
            /* Creating a new log message */
            free(lf->log);
            lf->log = strdup(_db_comment2);
            if(!lf->log)
            {
                merror(MEM_ERROR,ARGV0);
                return;
            }
           
            /* alert/ notify */ 
            if(Config.logbylevel <= Config.integrity)
                OS_Log(lf);
                
            if(Config.mailbylevel <= Config.integrity)
                OS_Createmail(&mailq, lf);

           
            return; 
        }
                       
        fgetpos(fp, &__initi_pos); /* getting next location */
        /* continuiing... */                                                
    }

    /* If we reach here, this file is not present on our database */
    fseek(fp, 0, SEEK_END);
    
    fprintf(fp,"%s %s\n",c_sum,f_name);

    return;
}


/* Special decoder for syscheck
 * Not using the default rendering tools for simplicity
 * and to be less resource intensive
 */
void DecodeSyscheck(Eventinfo *lf)
{
    char *c_sum;
    char *f_name;
   
    lf->type = SYSCHECK; 
    
    f_name = index(lf->log,' ');
    if(f_name == NULL)
    {
        merror("%s: Invalid integrity message received",ARGV0);
        return;
    }
    
    /* Zeroing to check the check sum */
    *f_name = '\0';
    f_name++;

    /* Checking if file is supposed to be ignored */
    if(Config.syscheck_ignore)
    {
        char **ff_ig = Config.syscheck_ignore;
        
        while(*ff_ig)
        {
            if(strcmp(*ff_ig, f_name) == 0)
            {
                return;
            }
            
            ff_ig++;
        }
    }
    
    c_sum = lf->log;
    
    DB_Search(f_name,c_sum,lf);
   
    /* Setting lf->log back correctly */
    f_name--; *f_name = ' ';

    return;
}

/* EOF */
