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

#include "eventinfo.h"
#include "os_regex/os_regex.h"
#include "config.h"
#include "alerts/alerts.h"


#define SYSCHECK_DIR    "/queue/syscheck"

/** Global variables **/
char _db_buf[1024];
char _db_comment[512];
char _db_comment2[512];

char _tmp_size[197];
char _tmp_perm[197];
char _tmp_owner[197];
char _tmp_gowner[197];
char _tmp_md5[197];


char *agent_ips[MAX_AGENTS +1];
FILE *agent_fps[MAX_AGENTS +1];

extern int mailq;
int db_err;


/* File search variables */
fpos_t __initi_pos;


/* SyscheckUpdateDaily
 * Clear unnecessary events from the queue
 */
void SyscheckUpdateDaily()
{
    return;
}


/* SyscheckInit
 * Initialize the necessary information to process the syscheck information
 */
void SyscheckInit()
{
    int i = 0;

    db_err = 0;
    
    for(;i <= MAX_AGENTS;i++)
    {
        agent_ips[i] = NULL;
        agent_fps[i] = NULL;
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
        if(strcmp(agent_ips[i], agent) == 0)
        {
            /* pointing to the beginning of the file */
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
            merror("%s: Unable to open '%s'",ARGV0,_db_buf);
            
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
    int p = 0;
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
        return;
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
        sn_size -= 1; /* 0 = \0, -1 = \n */
        if(saved_name[sn_size] == '\n')
            saved_name[sn_size] = '\0';
        
        
        if(strcmp(f_name,saved_name) == 0)
        {
            saved_name--;
            *saved_name = '\0';

            saved_sum = _db_buf;

            /* First three bytes are for frequency check */
            saved_sum+=3;

            /* checksum match, we can just return and keep going */
            if(strcmp(saved_sum,c_sum) == 0)
                return;

            /* If we reached here, the checksum of the file has changed */
            if(saved_sum[-3] == '!')
            {
                p++;
                if(saved_sum[-2] == '!')
                {
                    p++;
                    if(saved_sum[-1] == '!')    
                        p++;
                    else if(saved_sum[-1] == '?')
                        p+=2;    
                }
            }
            
            
            /* Checking the number of changes */
            if(p >= 1)
            {
                if(p >= 2)
                {
                    if(p >= 3)
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
      
      
            /* Adding new checksum to the database */
            /* Commenting the file entry and adding a new one latter */
            fsetpos(fp, &__initi_pos);
            fputc('#',fp);

            
            /* Adding the new entry at the end of the file */
            fseek(fp, 0, SEEK_END);
            fprintf(fp,"%c%c%c%s %s\n",
                        '!',
                        p >= 1? '!' : '+',
                        p == 2? '!' : (p > 2)?'?':'+',
                        c_sum,
                        f_name);
            
           
            /* File deleted */
            if(c_sum[0] == '-' && c_sum[1] == '1')
            {
                snprintf(_db_comment2, 512,
                            "File '%s' was deleted. Unable to retrieve "
                            "checksum.", f_name);
            }
            
            else    
            {
                /* Providing more info about the file change */
                char *oldsize = NULL, *newsize = NULL;
                char *olduid = NULL, *newuid = NULL;
                char *c_oldperm = NULL, *c_newperm = NULL;
                char *oldgid = NULL, *newgid = NULL;
                char *oldmd5 = NULL, *newmd5 = NULL;

                int oldperm = 0, newperm = 0;
                
                oldsize = saved_sum;
                newsize = c_sum;

                c_oldperm = index(saved_sum, ':');
                c_newperm = index(c_sum, ':');

                /* Get old/new permissions */
                if(c_oldperm && c_newperm)
                {
                    *c_oldperm = '\0';
                    c_oldperm++;

                    *c_newperm = '\0';
                    c_newperm++;

                    /* Get old/new uid/gid */
                    olduid = index(c_oldperm, ':');
                    newuid = index(c_newperm, ':');

                    if(olduid && newuid)
                    {
                        *olduid = '\0';
                        *newuid = '\0';

                        olduid++;
                        newuid++;

                        oldgid = index(olduid, ':');
                        newgid = index(newuid, ':');

                        if(oldgid && newgid)
                        {
                            *oldgid = '\0';
                            *newgid = '\0';

                            oldgid++;
                            newgid++;


                            /* Getting md5 */
                            oldmd5 = index(oldgid, ':');
                            newmd5 = index(newgid, ':');

                            if(oldmd5 && newmd5)
                            {
                                *oldmd5 = '\0';
                                *newmd5 = '\0';

                                oldmd5++;
                                newmd5++;    
                            }
                        }
                    }
                }

                /* Getting integer values */
                if(c_newperm && c_oldperm)
                {
                    newperm = atoi(c_newperm);
                    oldperm = atoi(c_oldperm);
                }
               
                /* Generating size message */
                if(strcmp(oldsize, newsize) == 0)
                {
                    _tmp_size[0] = '\0';
                }
                else
                {
                    snprintf(_tmp_size, 128,"Size changed from '%s' to '%s'\n",
                                            oldsize, newsize);
                }
                
                /* Permission message */
                if(oldperm == newperm)
                {
                    _tmp_perm[0] = '\0';
                }
                else if(oldperm > 0 && newperm > 0)
                {
                    snprintf(_tmp_perm, 196, "Permissions changed from "
                            "'%c%c%c%c%c%c%c%c%c' "
                            "to '%c%c%c%c%c%c%c%c%c'\n",
                            (oldperm & S_IRUSR)? 'r' : '-',
                            (oldperm & S_IWUSR)? 'w' : '-',
                            (oldperm & S_IXUSR)? 'x' : '-',
                            (oldperm & S_IRGRP)? 'r' : '-',
                            (oldperm & S_IWGRP)? 'w' : '-',
                            (oldperm & S_IXGRP)? 'x' : '-',
                            (oldperm & S_IROTH)? 'r' : '-',
                            (oldperm & S_IWOTH)? 'w' : '-',
                            (oldperm & S_IXOTH)? 'x' : '-',

                            (newperm & S_IRUSR)? 'r' : '-',
                            (newperm & S_IWUSR)? 'w' : '-',
                            (newperm & S_IXUSR)? 'x' : '-',
                            (newperm & S_IRGRP)? 'r' : '-',
                            (newperm & S_IWGRP)? 'w' : '-',
                            (newperm & S_IXGRP)? 'x' : '-',
                            (newperm & S_IROTH)? 'r' : '-',
                            (newperm & S_IWOTH)? 'w' : '-',
                            (newperm & S_IXOTH)? 'x' : '-');
                }
                
                /* Ownership message */
                if(strcmp(newuid, olduid) == 0)
                {
                    _tmp_owner[0] = '\0';
                }
                else
                {
                    snprintf(_tmp_owner, 128, "Ownership was '%s', "
                                              "now it is '%s'\n",
                                              olduid, newuid);
                }    
                
                /* group ownership message */
                if(strcmp(newgid, oldgid) == 0)
                {
                    _tmp_gowner[0] = '\0';
                }
                else
                {
                    snprintf(_tmp_gowner, 128, "Group ownership was '%s', "
                                               "now it is '%s'\n",
                                               oldgid, newgid);
                }
                
                /* md5 message */
                if(strcmp(newmd5, oldmd5) == 0)
                {
                    _tmp_md5[0] = '\0';
                }
                else
                {
                    snprintf(_tmp_md5, 195, "Old checksum was: '%s'\n"
                                            "New checksum is : '%s'\n",
                                            oldmd5, newmd5);
                }
                
                /* Provide information about the file */    
                snprintf(_db_comment2,512,"Integrity checksum changed for: "
                        "'%s'\n"
                        "%s"
                        "%s"
                        "%s"
                        "%s"
                        "%s",
                        f_name, 
                        _tmp_size,
                        _tmp_perm,
                        _tmp_owner,
                        _tmp_gowner,
                        _tmp_md5);
            }
            
            lf->comment = _db_comment; 

            lf->level = Config.integrity;

            lf->sigid = SYSCHECK_PLUGIN;

            
            /* Creating a new log message */
            free(lf->log);
            os_strdup(_db_comment2, lf->log);
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
        
    } /* continuiing... */

    /* If we reach here, this file is not present on our database */
    fseek(fp, 0, SEEK_END);
    
    fprintf(fp,"+++%s %s\n",c_sum,f_name);

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
