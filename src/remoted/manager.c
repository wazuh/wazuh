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
#include <time.h>

#include "remoted.h"

#include "os_net/os_net.h"
#include "headers/defs.h"
#include "headers/debug_op.h"
#include "headers/pthreads_op.h"

#include "os_crypto/md5/md5_op.h"
#include "error_messages/error_messages.h"

/* Internal structures */
typedef struct _file_sum
{
    int mark;
    char *name;
    os_md5 sum;
}file_sum;

typedef struct _mgr_thread
{
    int port;
    int agentid;
    char *srcip;
    char *msg;
}mgr_thread;


/* Global vars, acessible every where */
file_sum **f_sum;

time_t _ctime;
time_t _stime;


/* For the last message tracking */
char *_msg[MAX_AGENTS];
char *_ips[MAX_AGENTS];


/* free_thread: Frees the mgr_thread structure */
void free_thread(mgr_thread *h)
{
    if(h->msg)
        free(h->msg);
    if(h->srcip)
        free(h->srcip);
    
    return;        
}

/* last_messages: Check if the message received
 * is the same of the one received before.
 * If yes, return (1)
 */
int equal_last_msg(char *srcip, char *r_msg)
{
    int i;

    for(i = 0;i<MAX_AGENTS; i++)
    {
        if(!_ips[i])
        {
            _ips[i] = strdup(srcip);
            _msg[i] = strdup(r_msg);

            if(!_ips[i] || !_msg[i])
            {
                ErrorExit(MEM_ERROR, ARGV0);
                return(0);
            }
        }
        
        else if(strcmp(_ips[i], srcip) == 0)
        {
            if(strcmp(_msg[i], r_msg) == 0)
            {
                return(1);
            }
            
            free(_msg[i]);
            _msg[i] = strdup(r_msg);
            if(!_msg[i])
            {
                ErrorExit(MEM_ERROR, ARGV0);
                return(0);
            }
            return(0);
        }
    }

    merror("%s: Maximum number of agents reached.",ARGV0);
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

        printf("reading dir: %s\n",tmp_dir);
        
        if(OS_MD5_File(tmp_dir, md5sum) != 0)
        {
            merror("%s: Error accessing file '%s'",ARGV0, tmp_dir);
            continue;
        }
        
        printf("md5sum OK!\n");
        
        f_sum = (file_sum **)realloc(f_sum, (f_size +2) * sizeof(file_sum *));
        if(!f_sum)
        {
            ErrorExit(MEM_ERROR,ARGV0);
            return;
        }

        printf("a\n");
        f_sum[f_size] = calloc(1, sizeof(file_sum));
        if(!f_sum[f_size])
        {
            ErrorExit(MEM_ERROR,ARGV0);
            return;
        }

        printf("b\n");
        
        strncpy(f_sum[f_size]->sum, md5sum, 32);
        f_sum[f_size]->name = strdup(entry->d_name);
        if(!f_sum[f_size]->name)
        {
            ErrorExit(MEM_ERROR,ARGV0);
            return;
        }

        printf("c\n");
        f_sum[f_size]->mark = 0;
        f_size++;
    }
    
    printf("done!\n");
    if(f_sum != NULL)
        f_sum[f_size] = NULL;

    return;    
}

 
/* r_read: Returns a pointer to the string after the checksum
 * and after the randon number. Returns null on error. 
 */
char *r_read(char *tmp_msg)
{
    tmp_msg++;
    
    /* Removing checksum */
    tmp_msg = index(tmp_msg, ':');
    if(!tmp_msg)
    {
        return(NULL);
    }

    tmp_msg++;

    /* Removing randon */
    tmp_msg = index(tmp_msg, ':');
    if(!tmp_msg)
    {   
        return(NULL);
    }   
    
    tmp_msg++;
    
    return(tmp_msg);
}


/* send_file: Sends a file to the agent.
 * Returns -1 on error
 */
int send_file(int agentid, char *srcip, int port, char *name)
{
    int socket;
    char file[OS_MAXSTR +1];
    char buf[OS_MAXSTR +1];
    char *crypt_msg;

    int msg_size;
    FILE *fp;

    snprintf(file, OS_MAXSTR, "%s/%s",SHAREDCFG_DIR, name);

    fp = fopen(file, "r");
    if(!fp)
    {
        merror("%s: Impossible to open file '%s'",ARGV0, file);
        return(-1);
    }

    /* Connecting to the agent */
    socket = OS_ConnectUDP(port,srcip);
    if(socket < 0)
    {
        fclose(fp);
        merror(CONNS_ERROR,ARGV0,srcip);
        return(-1);
    }


    /* Sending the file name first */
    snprintf(buf, OS_MAXSTR, "#!-up file %s\n", name);

    crypt_msg = CreateSecMSG(&keys, buf, agentid, &msg_size);
    if(crypt_msg == NULL)
    {
        merror(SEC_ERROR,ARGV0);
        fclose(fp);
        close(socket);
        return(-1);
    }

    /* Sending initial message */
    if(OS_SendUDPbySize(socket, msg_size, crypt_msg) < 0)
    {
        free(crypt_msg);
        fclose(fp);
        merror(SEND_ERROR,ARGV0);
        close(socket);
        return(-1);
    }
    
    free(crypt_msg);

    /* Sending the file content */
    while(fgets(buf, OS_MAXSTR , fp) != NULL)
    {
        crypt_msg = CreateSecMSG(&keys, buf, agentid, &msg_size);

        if(crypt_msg == NULL)
        {
            fclose(fp);
            merror(SEC_ERROR,ARGV0);
            close(socket);
            return(-1);
        }

        if(OS_SendUDPbySize(socket, msg_size, crypt_msg) < 0)
        {
            fclose(fp);
            free(crypt_msg);
            merror("%s: Error sending message to agent (send)",ARGV0);
            close(socket);
            return(-1);
        }

        free(crypt_msg);
    }

    /* Sending the message to close the file */
    snprintf(buf, OS_MAXSTR, "#!-close file ");

    crypt_msg = CreateSecMSG(&keys, buf, agentid, &msg_size);
    if(crypt_msg == NULL)
    {
        merror(SEC_ERROR,ARGV0);
        fclose(fp);
        close(socket);
        return(-1);
    }

    /* Sending initial message */
    if(OS_SendUDPbySize(socket, msg_size, crypt_msg) < 0)
    {
        free(crypt_msg);
        merror(SEND_ERROR,ARGV0);
        close(socket);
        fclose(fp);
        return(-1);
    }
    
    free(crypt_msg);
    
    printf("file sent!\n");
    fclose(fp);
    close(socket);
    return(0);
}


/* mgr_thread: Reads message and manage the agent */
void *mgr_handle(void *arg)
{   
    int i;

    char *uname;

    mgr_thread *to_thread = (mgr_thread *)arg;
    
    char *msg = to_thread->msg;
            
    _ctime = time(0);
    if((_ctime - _stime) > (NOTIFY_TIME*2))
    {
        f_files();
        c_files();
        _stime = _ctime;
    }

    printf("message is now:%s\n",msg);

    /* Get uname */
    uname = to_thread->msg;
    msg = index(msg,'\n');
    if(!msg)
    {
        free_thread(to_thread);
        merror("%s: Invalid message from '%s' (uname)",ARGV0, to_thread->srcip);
        return(NULL);
    }

    *msg = '\0';
    msg++;

    printf("got uname!:%s\n",uname);


    /* XXX write uname somewhere */

    if(!f_sum)
    {
        /* Nothing to share with agent */
        return(NULL);
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
            merror("%s: Invalid message from '%s' (index \\n)",ARGV0, to_thread->srcip);
            break;
        }

        *msg = '\0';
        msg++;

        file = index(file, ' ');
        if(!file)
        {
            merror("%s: Invalid message from '%s' (index ' ')",ARGV0, to_thread->srcip);
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

    printf("if fsum\n");
    for(i = 0;;i++)
    {
        if(f_sum[i] == NULL)
            break;

        if((f_sum[i]->mark == 1) ||
                (f_sum[i]->mark == 0))
        {
            printf("sending file: '%s'\n",f_sum[i]->name);
            
            if(send_file(to_thread->agentid, to_thread->srcip, 
                         to_thread->port, f_sum[i]->name) < 0)
            {
                merror("%s: Error sending file '%s' to agent.",
                        ARGV0,
                        f_sum[i]->name);
            }
        }

        f_sum[i]->mark = 0;        
    }

    
    printf("message is: %s \n",msg);

    free_thread(to_thread);
    
    return(NULL); 
}


/* start_mgr: Start manager thread */
void start_mgr(int agentid, char *msg, char *srcip, int port)
{
    /* Nothing changed on the agent. Keep going */
    if(equal_last_msg(srcip, msg))
    {
        return;
    }

    else
    {
        mgr_thread to_thread;

        to_thread.agentid = agentid;
        to_thread.msg = strdup(msg);
        if(!to_thread.msg)
            ErrorExit(MEM_ERROR,ARGV0);
        to_thread.srcip = strdup(srcip);
        if(!to_thread.srcip)
            ErrorExit(MEM_ERROR,ARGV0);
        to_thread.port = port;

        /* Starting manager */
        if(CreateThread(mgr_handle, (void *)&to_thread) != 0)
        {
            ErrorExit("%s: Impossible to start the manager thread.");
        }
    }
    return;
}


/* manager_init: Should be called before anything here */
void manager_init()
{
    int i;
    _stime = time(0);
    c_files();

    for(i=0;i<MAX_AGENTS;i++)
    {
        _ips[i] = NULL;
        _msg[i] = NULL;
    }
}

/* EOF */
