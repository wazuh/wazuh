/*   $OSSEC, manager.c, v0.1, 2005/09/23, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pthread.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <time.h>
#include <signal.h>

#include "remoted.h"

#include "os_net/os_net.h"

#include "shared.h"

#include "os_crypto/md5/md5_op.h"

#define AGENTINFO_DIR    "/queue/agent-info"



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



/* clear_last_msg: Clear all cached messages
 */
void clear_last_msg()
{
    int i;

    /* Free msg if it is set */
    if(pthread_mutex_lock(&lastmsg_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
        return;
    }

    /* Clearing all last messages */
    for(i = 0;i<MAX_AGENTS; i++)
    {
        if(_msg[i])
        {
            free(_msg[i]);
            _msg[i] = NULL;
        }
        _changed[i] = 0;
    }

    /* Unlocking mutex */
    if(pthread_mutex_unlock(&lastmsg_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
        return;
    }

    return;
}



/* equal_last_msg: Check if the message received
 * is the same of the one received before.
 * If yes, return (1)
 */
int equal_last_msg(int agentid, char *r_msg)
{
    if(_msg[agentid])
    {
        /* Return 1 if we had this message already */
        if(strcmp(_msg[agentid], r_msg) == 0)
            return(1);

        /* Free msg if it is set */
        if(pthread_mutex_lock(&lastmsg_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(1);
        }
        
        free(_msg[agentid]);
        _msg[agentid] = NULL;

        /* Unlocking mutex */
        if(pthread_mutex_unlock(&lastmsg_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(1);
        }
        
                
    }

    /* Locking before using */
    if(pthread_mutex_lock(&lastmsg_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
        return(1);
    }
    
    
    /* Assign new values */
    _changed[agentid] = 1;
    _msg[agentid] = strdup(r_msg);
    if(!_msg[agentid])
    {
        merror(MEM_ERROR, ARGV0);
    }
    modified_agentid = agentid;
    
    
    /* Signal that new data is available */
    pthread_cond_signal(&awake_mutex);

    
    /* Unlocking mutex */
    if(pthread_mutex_unlock(&lastmsg_mutex) != 0)
    {
        merror(MUTEX_ERROR, ARGV0);
        return(1);
    }

    
    return(0);
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

    f_sum = NULL;

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
            return;
        }

        f_sum[f_size] = calloc(1, sizeof(file_sum));
        if(!f_sum[f_size])
        {
            ErrorExit(MEM_ERROR,ARGV0);
            return;
        }

        
        strncpy(f_sum[f_size]->sum, md5sum, 32);
        f_sum[f_size]->name = strdup(entry->d_name);
        if(!f_sum[f_size]->name)
        {
            ErrorExit(MEM_ERROR,ARGV0);
            return;
        }

        f_sum[f_size]->mark = 0;
        f_size++;
    }
    
    if(f_sum != NULL)
        f_sum[f_size] = NULL;

    closedir(dp);
    return;    
}

 

/* send_file: Sends a file to the agent.
 * Returns -1 on error
 */
int send_file(int agentid, char *name, char *sum)
{
    int i = 0;
    char file[OS_MAXSTR +1];
    char buf[OS_MAXSTR +1];
    char crypt_msg[OS_MAXSTR +1];

    int msg_size;
    
    FILE *fp;

    snprintf(file, OS_MAXSTR, "%s/%s",SHAREDCFG_DIR, name);

    fp = fopen(file, "r");
    if(!fp)
    {
        merror("%s: Unable to open file '%s'",ARGV0, file);
        return(-1);
    }


    /* Sending the file name first */
    snprintf(buf, OS_MAXSTR, "#!-up file %s %s\n", sum, name);

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
        merror(SEND_ERROR,ARGV0);
        return(-1);
    }
    
    sleep(1);

    /* Sending the file content */
    while(fgets(buf, OS_MAXSTR , fp) != NULL)
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
            merror("%s: Error sending message to agent (send)",ARGV0);
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
    snprintf(buf, OS_MAXSTR, "#!-close file ");

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
        merror(SEND_ERROR,ARGV0);
        fclose(fp);
        return(-1);
    }
    
    fclose(fp);
    
    return(0);
}



/** void *wait_for_msgs(void *none) v0.1
 * Wait for new messages to read
 */
void *wait_for_msgs(void *none)
{
    int id, i;
    char msg[OS_MAXSTR +2];
    

    /* Initializing the memory */
    memset(msg, '\0', OS_MAXSTR +2);

    
    /* should never leave this loop */
    while(1)
    {
        merror("wait_for_msgs: waiting for msg");

        /* Every 60 minutes, re read the files.
         * If something change, notify all agents 
         */
        _ctime = time(0);
        if((_ctime - _stime) > (NOTIFY_TIME*6))
        {
            f_files();
            c_files();

            clear_last_msg();                
        }
        
        /* locking mutex */
        if(pthread_mutex_lock(&lastmsg_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(NULL);
        }

        /* If no agent is available, wait for signal */
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

        merror("wait_for_msgs: msg received..");


        /* Checking if any other agent is ready */
        for(i = 0;i<MAX_AGENTS; i++)
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
                strncpy(msg, _msg[i], OS_MAXSTR);
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



/** void read_contromsg(int agentid, char *msg) v0.2.
 * Reads the available control message from
 * the agent.
 */
void read_controlmsg(int agentid, char *msg)
{   
    int i;

    char *uname;
    char agent_file[OS_MAXSTR +1];

    FILE *fp;
    
    
    /* Get uname */
    merror("msg: %s!!", msg);

    uname = msg;
    msg = index(msg,'\n');
    if(!msg)
    {
        merror("%s: Invalid message from '%s' (uname)",ARGV0, 
                                                       keys.ips[agentid]);
        return;
    }

    *msg = '\0';
    msg++;

    /* Writting to the agent file */
    snprintf(agent_file, OS_MAXSTR, "%s/%s",
                         AGENTINFO_DIR,
                         keys.ips[agentid]);
        
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

        msg = index(msg, '\n');
        if(!msg)
        {
            merror("%s: Invalid message from '%s' (index \\n)",
                        ARGV0, 
                        keys.ips[agentid]);
            break;
        }

        *msg = '\0';
        msg++;

        file = index(file, ' ');
        if(!file)
        {
            merror("%s: Invalid message from '%s' (index ' ')",
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
            
            if(send_file(agentid,f_sum[i]->name,f_sum[i]->sum) < 0)
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



/* save_controlmsg: Save a control message received
 * from an agent. read_contromsg (other thread) is going
 * to deal with it.
 */
void save_controlmsg(int agentid, char *msg)
{
    /* Notify other thread that something changed */
    merror("saving msg: %s", msg);
    equal_last_msg(agentid, msg);
    
    return;
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
