/* @(#) $Id$ */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "read-agents.h"


/* Free the agent list in memory
 */
void free_agents(char **agent_list)
{
    int i;
    if(!agent_list)
        return;
        
    for(i = 0;;i++)
    {
        if(agent_list[i] == NULL)
            break;

        free(agent_list[i]);
    }

    free(agent_list);
    agent_list = NULL;
}


/* Delete syscheck db */ 
int delete_syscheck(char *sk_name, char *sk_ip, int full_delete)
{
    FILE *fp;
    char tmp_file[513];

    tmp_file[512] = '\0';
    
    /* Deleting related files */
    snprintf(tmp_file, 512, "%s/(%s) %s->syscheck",
            SYSCHECK_DIR,
            sk_name,
            sk_ip);

    fp = fopen(tmp_file, "w");
    if(fp)
        fclose(fp);

    if(full_delete)    
        unlink(tmp_file);


    /* Deleting cpt files */
    snprintf(tmp_file, 512, "%s/.(%s) %s->syscheck.cpt",
            SYSCHECK_DIR,
            sk_name,
            sk_ip);

    fp = fopen(tmp_file, "w");
    if(fp)
        fclose(fp);
    unlink(tmp_file);


    /* Deleting registry entries */
    snprintf(tmp_file, 512, "%s/(%s) %s->syscheck-registry",
            SYSCHECK_DIR,
            sk_name,
            sk_ip);

    fp = fopen(tmp_file, "w");
    if(fp)
        fclose(fp);
    if(full_delete)
        unlink(tmp_file);


    /* Deleting cpt files */
    snprintf(tmp_file, 512, "%s/.(%s) %s->syscheck-registry.cpt",
            SYSCHECK_DIR,
            sk_name,
            sk_ip);

    fp = fopen(tmp_file, "w");
    if(fp)
        fclose(fp);
    unlink(tmp_file);

    return(1);
}


/* Delete agent.
 */
int delete_agentinfo(char *name)
{
    char *sk_name;
    char *sk_ip;
    char tmp_file[513];

    tmp_file[512] = '\0';


    /* Deleting agent info */
    snprintf(tmp_file, 512, "%s/%s", AGENTINFO_DIR, name);
    unlink(tmp_file);


    /* Deleting syscheck */
    sk_name = name;
    sk_ip = strrchr(name, '-');
    if(!sk_ip)
        return(0);

    *sk_ip = '\0';
    sk_ip++;


    /* Deleting syscheck */
    delete_syscheck(sk_name, sk_ip, 1);
    
    return(1);
}
 

/* List available agents.
 */
char **get_agents(int flag)
{
    int f_size = 0;
    
    char **f_files = NULL;
    DIR *dp;

    struct dirent *entry;
    
    /* Opening the directory given */
    dp = opendir(AGENTINFO_DIR);
    if(!dp) 
    {
        merror("%s: Error opening directory: '%s': %s ",
                __local_name,
                AGENTINFO_DIR,
                strerror(errno));
        return(NULL);
    }   


    /* Reading directory */
    while((entry = readdir(dp)) != NULL)
    {
        char tmp_file[513];
        tmp_file[512] = '\0';
        
        /* Just ignore . and ..  */
        if((strcmp(entry->d_name,".") == 0) ||
           (strcmp(entry->d_name,"..") == 0))
            continue;

        snprintf(tmp_file, 512, "%s/%s", AGENTINFO_DIR, entry->d_name);

        if(flag != GA_ALL)
        {
            struct stat file_status;

            if(stat(tmp_file, &file_status) < 0)
                continue;
            
            if(file_status.st_mtime > (time(0) - (3*NOTIFY_TIME + 30)))
            {
                if(flag == GA_NOTACTIVE)
                    continue;
            }
            else
            {
                if(flag == GA_ACTIVE)
                    continue;
            }
        }
        
        f_files = (char **)realloc(f_files, (f_size +2) * sizeof(char *));
        if(!f_files)
        {
            ErrorExit(MEM_ERROR, __local_name);
        }

        os_strdup(entry->d_name, f_files[f_size]);
        f_files[f_size +1] = NULL;
        
        f_size++;
    }
    
    closedir(dp);
    return(f_files);    
}

 

/* EOF */
