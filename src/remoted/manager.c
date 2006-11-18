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
#include <pthread.h>

#include "remoted.h"
#include "os_net/os_net.h"
#include "os_crypto/md5/md5_op.h"


/* Internal structures */
typedef struct _file_sum
{
    int mark;
    char *name;
    os_md5 sum;
}file_sum;



/* Internal functions prototypes */
void read_controlmsg(int agentid, char *msg);




/* Global vars, acessible every where */
file_sum **f_sum;

time_t _ctime;
time_t _stime;



/* For the last message tracking */
char *_msg[MAX_AGENTS];
int _changed[MAX_AGENTS];
int modified_agentid;


/* pthread mutex variables */
pthread_mutex_t lastmsg_mutex;
pthread_cond_t awake_mutex;



/* save_controlmsg: Save a control message received
 * from an agent. read_contromsg (other thread) is going
 * to deal with it (only if message changed).
 */
void save_controlmsg(int agentid, char *r_msg)
{
    /* Locking before using */
    if(pthread_mutex_lock(&lastmsg_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
        return;
    }

     
    if(_msg[agentid])
    {
        /* Check if message changed */
        if(strcmp(_msg[agentid], r_msg) != 0)
        {
            free(_msg[agentid]);
            os_strdup(r_msg, _msg[agentid]);    
        }
    }
    /* If message does not exist, create it */
    else
    {
        os_strdup(r_msg, _msg[agentid]);
    }
    
    
    /* Assign new values */
    _changed[agentid] = 1;
    modified_agentid = agentid;


    /* Signal that new data is available */
    pthread_cond_signal(&awake_mutex);

    
    /* Unlocking mutex */
    if(pthread_mutex_unlock(&lastmsg_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
        return;
    }

    
    return;
}    



/* f_files: Free the files memory
 */
void f_files()
{
    int i;
    if(!f_sum)
        return;
    for(i = 0;;i++)    
    {
        if(f_sum[i] == NULL)
            break;
        
        if(f_sum[i]->name)
            free(f_sum[i]->name);
            
        free(f_sum[i]);
        f_sum[i] = NULL;
    }

    free(f_sum);
    f_sum = NULL;
}



/* c_files: Create the structure with the files and checksums
 * Returns void
 */
void c_files()
{
    DIR *dp;

    struct dirent *entry;
    
    os_md5 md5sum;
    
    int f_size = 0;


    f_sum = NULL;

    /* Opening the directory given */
    dp = opendir(SHAREDCFG_DIR);
    if(!dp) 
    {
        merror("%s: Error opening directory: '%s': %s ",
                ARGV0,
                SHAREDCFG_DIR,
                strerror(errno));
        return;
    }   


    /* Reading directory */
    while((entry = readdir(dp)) != NULL)
    {
        char tmp_dir[512];
        
        /* Just ignore . and ..  */
        if((strcmp(entry->d_name,".") == 0) ||
                (strcmp(entry->d_name,"..") == 0))
            continue;

        snprintf(tmp_dir, 512, "%s/%s", SHAREDCFG_DIR, entry->d_name);

        
        if(OS_MD5_File(tmp_dir, md5sum) != 0)
        {
            merror("%s: Error accessing file '%s'",ARGV0, tmp_dir);
            continue;
        }
        
        
        f_sum = (file_sum **)realloc(f_sum, (f_size +2) * sizeof(file_sum *));
        if(!f_sum)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        f_sum[f_size] = calloc(1, sizeof(file_sum));
        if(!f_sum[f_size])
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        
        strncpy(f_sum[f_size]->sum, md5sum, 32);
        f_sum[f_size]->name = strdup(entry->d_name);
        if(!f_sum[f_size]->name)
        {
            ErrorExit(MEM_ERROR,ARGV0);
        }

        f_sum[f_size]->mark = 0;
        f_size++;
    }
    
    if(f_sum != NULL)
        f_sum[f_size] = NULL;

    closedir(dp);
    return;    
}

 

/* send_file_toagent: Sends a file to the agent.
 * Returns -1 on error
 */
int send_file_toagent(int agentid, char *name, char *sum)
{
    int i = 0;
    char file[OS_SIZE_1024 +1];
    char buf[OS_SIZE_1024 +1];
    char crypt_msg[OS_MAXSTR +1];

    int msg_size;
    
    FILE *fp;

    
    /* If rcvd is not set, do not send (agent didn't connect to me yet */
    if(keys.rcvd[agentid] < (time(0) - (2*NOTIFY_TIME)))
    {
        return(-1);    
    }
    
    
    snprintf(file, OS_SIZE_1024, "%s/%s",SHAREDCFG_DIR, name);

    fp = fopen(file, "r");
    if(!fp)
    {
        merror(FOPEN_ERROR, ARGV0, file);
        return(-1);
    }


    /* Sending the file name first */
    snprintf(buf, OS_SIZE_1024, "%s%s%s %s\n", 
                             CONTROL_HEADER, FILE_UPDATE_HEADER, sum, name);

    msg_size = CreateSecMSG(&keys, buf, crypt_msg, agentid);
    if(msg_size == 0)
    {
        merror(SEC_ERROR,ARGV0);
        fclose(fp);
        return(-1);
    }

    /* Sending initial message */
    if(sendto(logr.sock, crypt_msg, msg_size, 0,
                         (struct sockaddr *)&keys.peer_info[agentid],
                         logr.peer_size) < 0) 
    {
        fclose(fp);
        merror(SEND_ERROR,ARGV0, keys.ids[agentid]);
        return(-1);
    }
    
    sleep(1);

    /* Sending the file content */
    while(fgets(buf, OS_SIZE_1024 , fp) != NULL)
    {
        msg_size = CreateSecMSG(&keys, buf, crypt_msg, agentid);

        if(msg_size == 0)
        {
            fclose(fp);
            merror(SEC_ERROR,ARGV0);
            return(-1);
        }

        if(sendto(logr.sock, crypt_msg, msg_size, 0,
                         (struct sockaddr *)&keys.peer_info[agentid],
                         logr.peer_size) < 0)  
        {
            fclose(fp);
            merror(SEND_ERROR,ARGV0, keys.ids[agentid]);
            return(-1);
        }


        /* Sleep 1 every 5 messages -- no flood */
        if(i > 4)
        {
            sleep(1);
            i = 0;
        }
        i++;
    }

    sleep(1);
    
    /* Sending the message to close the file */
    snprintf(buf, OS_SIZE_1024, "%s%s", CONTROL_HEADER, FILE_CLOSE_HEADER);

    msg_size = CreateSecMSG(&keys, buf, crypt_msg, agentid);
    if(msg_size == 0)
    {
        merror(SEC_ERROR,ARGV0);
        fclose(fp);
        return(-1);
    }

    /* Sending final message */
    if(sendto(logr.sock, crypt_msg, msg_size, 0,
                         (struct sockaddr *)&keys.peer_info[agentid],
                         logr.peer_size) < 0) 
    {
        merror(SEND_ERROR,ARGV0, keys.ids[agentid]);
        fclose(fp);
        return(-1);
    }
    
    fclose(fp);
    
    return(0);
}



/** void read_contromsg(int agentid, char *msg) v0.2.
 * Reads the available control message from
 * the agent.
 */
void read_controlmsg(int agentid, char *msg)
{   
    int i;

    char *uname;
    char agent_file[OS_SIZE_1024 +1];
    char msg_ack[OS_FLSIZE +1];

    FILE *fp;
    
    msg_ack[OS_FLSIZE] = '\0';

    
    /* Startup message  -- communicate back to the agent */
    if(strcmp(msg, HC_STARTUP) == 0)
    {
        snprintf(msg_ack, OS_FLSIZE, "%s%s", CONTROL_HEADER, HC_ACK);
        send_msg(agentid, msg_ack);
        
        return;    
    }
    
    
    /* Get uname */
    uname = msg;
    msg = strchr(msg,'\n');
    if(!msg)
    {
        merror("%s: Invalid message from '%s' (uname)",ARGV0, 
                                                       keys.ips[agentid]);
        return;
    }


    /* Uname received, send ok to agent */
    snprintf(msg_ack, OS_FLSIZE, "%s%s", CONTROL_HEADER, HC_ACK);
    send_msg(agentid, msg_ack);
    

    *msg = '\0';
    msg++;


    /* Writting to the agent file */
    snprintf(agent_file, OS_SIZE_1024, "%s/%s-%s",
                         AGENTINFO_DIR,
                         keys.name[agentid],
                         keys.ips[agentid]->ip);
        
    fp = fopen(agent_file, "w");
    if(fp)
    {
        fprintf(fp, "%s\n", uname);
        fclose(fp);
    }        

    if(!f_sum)
    {
        /* Nothing to share with agent */
        return;
    }

    /* Parse message */ 
    while(*msg != '\0')
    {
        char *md5;
        char *file;

        md5 = msg;
        file = msg;

        msg = strchr(msg, '\n');
        if(!msg)
        {
            merror("%s: Invalid message from '%s' (strchr \\n)",
                        ARGV0, 
                        keys.ips[agentid]);
            break;
        }

        *msg = '\0';
        msg++;

        file = strchr(file, ' ');
        if(!file)
        {
            merror("%s: Invalid message from '%s' (strchr ' ')",
                        ARGV0, 
                        keys.ips[agentid]);
            break;
        }

        *file = '\0';
        file++;

        for(i = 0;;i++)
        {
            if(f_sum[i] == NULL)
                break;

            else if(strcmp(f_sum[i]->name, file) != 0)
                continue;

            else if(strcmp(f_sum[i]->sum, md5) != 0)
                f_sum[i]->mark = 1; /* Marked to update */

            else
            {
                f_sum[i]->mark = 2;
            }
            break;        
        }
    }

    /* Updating each file marked */
    for(i = 0;;i++)
    {
        if(f_sum[i] == NULL)
            break;

        if((f_sum[i]->mark == 1) ||
           (f_sum[i]->mark == 0))
        {
            
            if(send_file_toagent(agentid,f_sum[i]->name,f_sum[i]->sum) < 0)
            {
                merror("%s: Error sending file '%s' to agent.",
                        ARGV0,
                        f_sum[i]->name);
            }
        }

        f_sum[i]->mark = 0;        
    }

    
    return; 
}



/** void *wait_for_msgs(void *none) v0.1
 * Wait for new messages to read.
 * The messages are going to be sent from save_controlmsg.
 */
void *wait_for_msgs(void *none)
{
    int id, i;
    char msg[OS_SIZE_1024 +2];
    

    /* Initializing the memory */
    memset(msg, '\0', OS_SIZE_1024 +2);

    
    /* should never leave this loop */
    while(1)
    {
        /* Every 60 minutes, re read the files.
         * If something change, notify all agents 
         */
        _ctime = time(0);
        if((_ctime - _stime) > (NOTIFY_TIME*6))
        {
            f_files();
            c_files();

            _stime = _ctime;
        }
        
        
        /* locking mutex */
        if(pthread_mutex_lock(&lastmsg_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(NULL);
        }

        /* If no agent changed, wait for signal */
        if(modified_agentid == -1)
        {
            pthread_cond_wait(&awake_mutex, &lastmsg_mutex);
        }


        /* Unlocking mutex */
        if(pthread_mutex_unlock(&lastmsg_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(NULL);
        }


        /* Checking if any agent is ready */
        for(i = 0;i<keys.keysize; i++)
        {
            id = 0;
            
            /* locking mutex */
            if(pthread_mutex_lock(&lastmsg_mutex) != 0)
            {
                merror(MUTEX_ERROR, ARGV0);
                break;
            }

            if((_changed[i] == 1)&&(_msg[i]))
            {
                /* Copying the message to be analyzed */
                strncpy(msg, _msg[i], OS_SIZE_1024);
                _changed[i] = 0;

                if(modified_agentid >= i)
                    modified_agentid = -1;

                id = 1;
            }
            
            /* Unlocking mutex */
            if(pthread_mutex_unlock(&lastmsg_mutex) != 0)
            {
                merror(MUTEX_ERROR, ARGV0);
                break;
            }

            if(id)
            {
                read_controlmsg(i, msg);
            }
        }
    }

    return(NULL);
}



/* manager_init: Should be called before anything here */
void manager_init()
{
    int i;
    _stime = time(0);
    c_files();

    debug1("%s: DEBUG: Starting manager_unit", ARGV0);

    for(i=0;i<MAX_AGENTS;i++)
    {
        _msg[i] = NULL;
        _changed[i] = 0;
    }

    /* Initializing mutexes */
    pthread_mutex_init(&lastmsg_mutex, NULL);
    pthread_cond_init (&awake_mutex, NULL);

    modified_agentid = -1;

    return;
}



/* EOF */
