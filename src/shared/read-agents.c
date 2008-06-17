/* @(#) $Id$ */

/* Copyright (C) 2005-2008 Third Brigade, Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "read-agents.h"
#include "os_net/os_net.h"


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
        agent_list[i] = NULL;
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

 

/** char *print_agent_status(int status)
 * Prints the text representation of the agent status.
 */
char *print_agent_status(int status)
{
    char *status_str = "Never connected";

    if(status == GA_STATUS_ACTIVE)
    {
        status_str = "Active";
    }
    else if(status == GA_STATUS_NACTIVE)
    {
        status_str = "Disconnected";
    }

    return(status_str);
}


/* non-windows functions from now on. */
#ifndef WIN32


/** int send_msg_to_agent(int socket, char *msg)
 * Sends a message to an agent.
 * returns -1 on error.
 */
int send_msg_to_agent(int msocket, char *msg, char *agt_id)
{
    int rc;
    char agt_msg[OS_SIZE_1024 +1];

    agt_msg[OS_SIZE_1024] = '\0';
    
    snprintf(agt_msg, OS_SIZE_1024,
            "%s %c%c%c %s %s",
            "(msg_to_agent) []",
            (agt_id == NULL)?ALL_AGENTS_C:NONE_C,
            NO_AR_C,
            (agt_id != NULL)?SPECIFIC_AGENT_C:NONE_C,
            agt_id != NULL? agt_id: "(null)",
            msg);

    if((rc = OS_SendUnix(msocket, agt_msg, 0)) < 0)
    {
        if(rc == OS_SOCKBUSY)
        {
            merror("%s: ERROR: Remoted socket busy.", __local_name);
        }
        else
        {
            merror("%s: ERROR: Remoted socket error.", __local_name);
        }
        merror("%s: Error communicating with remoted queue (%d).",
               __local_name, rc);

        return(-1);
    }

    return(0);
}



/** int connect_to_remoted()
 * Connects to remoted to be able to send messages to the agents.
 * Returns the socket on success or -1 on failure.
 */
int connect_to_remoted()
{
    int arq = -1;
    
    if((arq = StartMQ(ARQUEUE, WRITE)) < 0)
    {
        merror(ARQ_ERROR, __local_name);
        return(-1);
    }

    return(arq);
}


#endif


/* Internal funtion. Extract last time of scan from rootcheck/syscheck. */
int _get_time_rkscan(char *agent_name, char *agent_ip, agent_info *agt_info)
{
    FILE *fp;
    char buf[1024 +1];


    /* Agent name of null, means it is the server info. */
    if(agent_name == NULL)
    {
        snprintf(buf, 1024, "%s/rootcheck", 
                      ROOTCHECK_DIR);
    }
    else
    {
        snprintf(buf, 1024, "%s/(%s) %s->rootcheck", 
                      ROOTCHECK_DIR, agent_name, agent_ip);
    }
    

    /* If file is not there, set to unknown. */
    fp = fopen(buf, "r");
    if(!fp)
    {
        os_strdup("Unknown", agt_info->rootcheck_time);
        os_strdup("Unknown", agt_info->rootcheck_endtime);
        os_strdup("Unknown", agt_info->syscheck_time);
        os_strdup("Unknown", agt_info->syscheck_endtime);
        return(0);
    }
    

    while(fgets(buf, 1024, fp) != NULL)
    {
        char *tmp_str = NULL;

        /* Removing new line. */
        tmp_str = strchr(buf, '\n');
        if(tmp_str)
            *tmp_str = '\0';


        tmp_str = strstr(buf, "Starting syscheck scan");
        if(tmp_str)
        {
            time_t s_time = 0;
            tmp_str = buf + 1;

            s_time = (time_t)atoi(tmp_str);

            os_strdup(ctime(&s_time), agt_info->syscheck_time);

            /* Removing new line. */
            tmp_str = strchr(agt_info->syscheck_time, '\n');
            if(tmp_str)
                *tmp_str = '\0';
                
            continue;
        }

        tmp_str = strstr(buf, "Ending syscheck scan");
        if(tmp_str)
        {
            time_t s_time = 0;
            tmp_str = buf + 1;

            s_time = (time_t)atoi(tmp_str);

            os_strdup(ctime(&s_time), agt_info->syscheck_endtime);

            /* Removing new line. */
            tmp_str = strchr(agt_info->syscheck_endtime, '\n');
            if(tmp_str)
                *tmp_str = '\0';
                
            continue;
        }
        

        tmp_str = strstr(buf, "Starting rootcheck scan");
        if(tmp_str)
        {
            time_t s_time = 0;
            tmp_str = buf + 1;

            s_time = (time_t)atoi(tmp_str);

            os_strdup(ctime(&s_time), agt_info->rootcheck_time);

            /* Removing new line. */
            tmp_str = strchr(agt_info->rootcheck_time, '\n');
            if(tmp_str)
                *tmp_str = '\0';

            continue;
        }

        tmp_str = strstr(buf, "Ending rootcheck scan");
        if(tmp_str)
        {
            time_t s_time = 0;
            tmp_str = buf + 1;

            s_time = (time_t)atoi(tmp_str);

            os_strdup(ctime(&s_time), agt_info->rootcheck_endtime);

            /* Removing new line. */
            tmp_str = strchr(agt_info->rootcheck_endtime, '\n');
            if(tmp_str)
                *tmp_str = '\0';

            continue;
        }
    }


    /* Setting unknown values. */
    if(!agt_info->rootcheck_time)
        os_strdup("Unknown", agt_info->rootcheck_time);
    if(!agt_info->rootcheck_endtime)
        os_strdup("Unknown", agt_info->rootcheck_endtime);
    if(!agt_info->syscheck_time)
        os_strdup("Unknown", agt_info->syscheck_time);
    if(!agt_info->syscheck_endtime)
        os_strdup("Unknown", agt_info->syscheck_endtime);
            
    fclose(fp);
    return(0);
}



/* Internal funtion. Extract last time of scan from rootcheck/syscheck. */
char *_get_agent_keepalive(char *agent_name, char *agent_ip)
{
    char buf[1024 +1];
    struct stat file_status;


    /* No keep alive for the server. */
    if(!agent_name)
    {
        return(strdup("Not available"));
    }
    
    snprintf(buf, 1024, "%s/%s-%s", AGENTINFO_DIR, agent_name, agent_ip);
    if(stat(buf, &file_status) < 0)
    {
        return(strdup("Unknown"));
    }


    return(strdup(ctime(&file_status.st_mtime)));
}



/* Internal funtion. Extracts operating system. */
int _get_agent_os(char *agent_name, char *agent_ip, agent_info *agt_info)
{
    FILE *fp;
    char buf[1024 +1];

    
    /* Getting server info. */
    if(!agent_name)
    {
        char *ossec_version = NULL;
        agt_info->os = getuname();
        os_strdup(__name " " __version, agt_info->version);


        /* Removing new line. */
        ossec_version = strchr(agt_info->os, '\n');
        if(ossec_version)
            *ossec_version = '\0';


        ossec_version = strstr(agt_info->os, " - ");
        if(ossec_version)
        {
            *ossec_version = '\0';
        }


        if(strlen(agt_info->os) > 55)
        {
            agt_info->os[52] = '.';
            agt_info->os[53] = '.';
            agt_info->os[54] = '\0';
        }


        return(0);
    }

    
    snprintf(buf, 1024, "%s/%s-%s", AGENTINFO_DIR, agent_name, agent_ip);
    fp = fopen(buf, "r");
    if(!fp)
    {
        os_strdup("Unknown", agt_info->os);
        os_strdup("Unknown", agt_info->version);
        return(0);
    }
    
    
    if(fgets(buf, 1024, fp))
    {
        char *ossec_version = NULL;

        /* Removing new line. */
        ossec_version = strchr(buf, '\n');
        if(ossec_version)
            *ossec_version = '\0';
        
        
        ossec_version = strstr(buf, " - ");
        if(ossec_version)
        {
            *ossec_version = '\0';
            ossec_version += 3;

            os_calloc(1024 +1, sizeof(char), agt_info->version);
            strncpy(agt_info->version, ossec_version, 1024);
        }


        if(strlen(buf) > 55)
        {
            buf[52] = '.';
            buf[53] = '.';
            buf[54] = '\0';
        }

        os_strdup(buf, agt_info->os);
        fclose(fp);

        return(1);
    }

    fclose(fp);
    
    os_strdup("Unknown", agt_info->os);
    os_strdup("Unknown", agt_info->version);
    
    return(0);
}



/** agent_info *get_agent_info(char *agent_name, char *agent_ip)
 * Get information from an agent.
 */
agent_info *get_agent_info(char *agent_name, char *agent_ip)
{
    char tmp_file[513];
    char *agent_ip_pt = NULL;
    char *tmp_str = NULL;
    
    agent_info *agt_info = NULL;

    tmp_file[512] = '\0';


    /* Removing the  "/", since it is not present on the file. */
    if((agent_ip_pt = strchr(agent_ip, '/')))
    {
        *agent_ip_pt = '\0';
    }


    /* Allocating memory for the info structure. */
    agt_info = calloc(1, sizeof(agent_info));


    /* Zeroing the values. */
    agt_info->rootcheck_time = NULL;
    agt_info->rootcheck_endtime = NULL;
    agt_info->syscheck_time = NULL;
    agt_info->syscheck_endtime = NULL;
    agt_info->os = NULL;
    agt_info->version = NULL;
    agt_info->last_keepalive = NULL;


    /* Getting information about the OS. */
    _get_agent_os(agent_name, agent_ip, agt_info);
    _get_time_rkscan(agent_name, agent_ip, agt_info);
    agt_info->last_keepalive = _get_agent_keepalive(agent_name, agent_ip);


    /* Removing new line from keep alive. */
    tmp_str = strchr(agt_info->last_keepalive, '\n');
    if(tmp_str)
        *tmp_str = '\0';

        

    /* Setting back the ip address. */
    if(agent_ip_pt)
    {
        *agent_ip_pt = '/';
    }


    return(agt_info);
}



/** int get_agent_status(char *agent_name, char *agent_ip)
 * Gets the status of an agent, based on the name/ip.
 */
int get_agent_status(char *agent_name, char *agent_ip)
{
    char tmp_file[513];
    char *agent_ip_pt = NULL;
    
    struct stat file_status;

    tmp_file[512] = '\0';


    /* Server info. */
    if(agent_name == NULL)
    {
        return(GA_STATUS_ACTIVE);     
    }
    

    /* Removing the  "/", since it is not present on the file. */
    if((agent_ip_pt = strchr(agent_ip, '/')))
    {
        *agent_ip_pt = '\0';
    }

    snprintf(tmp_file, 512, "%s/%s-%s", AGENTINFO_DIR, agent_name, agent_ip);


    /* Setting back the ip address. */
    if(agent_ip_pt)
    {
        *agent_ip_pt = '/';
    }


    if(stat(tmp_file, &file_status) < 0)
    {
        return(GA_STATUS_INV);
    }
    

    if(file_status.st_mtime > (time(0) - (3*NOTIFY_TIME + 30)))
    {
        return(GA_STATUS_ACTIVE);
    }

    return(GA_STATUS_NACTIVE);
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
        int status = 0;
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
                status = 1;
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


        /* Adding agent entry */
        if(flag == GA_ALL_WSTATUS)
        {
           char agt_stat[512];
           
           snprintf(agt_stat, sizeof(agt_stat) -1, "%s %s",
                    entry->d_name, status == 1?"active":"disconnected"); 

           os_strdup(agt_stat, f_files[f_size]);
        }
        else
        {
            os_strdup(entry->d_name, f_files[f_size]);
        }
        
        f_files[f_size +1] = NULL;
        
        f_size++;
    }
    
    closedir(dp);
    return(f_files);
}

 
/* EOF */
