/*   $OSSEC, execd.c, v0.2, 2005/11/01, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include <sys/types.h>
#include <sys/socket.h>
#include <sys/wait.h>

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "shared.h"
#include "list_op.h"

#include "os_regex/os_regex.h"
#include "os_net/os_net.h"

#include "execd.h"



/* Timeout data structure */
typedef struct _timeout_data
{
    time_t time_of_addition;
    int time_to_block;
    char **command;
}timeout_data;




/** int main(int argc, char **argv) v0.1
 */
int main(int argc, char **argv)
{
    int c;
    int gid = 0,m_queue = 0;
    char *dir  = DEFAULTDIR;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTARPATH;


    while((c = getopt(argc, argv, "dhu:g:D:c:")) != -1){
        switch(c){
            case 'h':
                help();
                break;
            case 'd':
                nowDebug();
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group = optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir = optarg;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            default:
                help();
                break;
        }

    }

    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);

    /* Check if the group given are valid */
    gid = Privsep_GetGroup(group);
    if(gid < 0)
        ErrorExit(USER_ERROR,ARGV0,"",group);


    /* Privilege separation */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);


    /* Starting queue (exec queue) */
    if((m_queue = StartMQ(EXECQUEUEPATH,READ)) < 0)
        ErrorExit(QUEUE_ERROR,ARGV0,EXECQUEUEPATH);


    /* Signal manipulation */
    StartSIG(ARGV0);


    /* Going daemon */
    nowDaemon();
    goDaemon();

    
    /* Creating the PID file */
    if(CreatePID(ARGV0, getpid()) < 0)
        merror(PID_ERROR,ARGV0);


    /* The real daemon Now */	
    ExecdStart(m_queue);
    
    exit(0);
}




/** void FreeTimeoutEntry(timeout_data *timeout_entry) v0.1
 * Free the timeout entry. Must be called after popping it
 * from the timeout list
 */
void FreeTimeoutEntry(timeout_data *timeout_entry)
{
    char **tmp_str;

    if(!timeout_entry)
    {
        return;
    }
    
    tmp_str = timeout_entry->command;

    /* Clearing the command arguments */
    if(tmp_str)
    {
        while(*tmp_str)
        {
            free(*tmp_str);
            *tmp_str = NULL;

            tmp_str++;
        }
    }

    free(timeout_entry);
    timeout_entry = NULL;

    return;
}




/** void ExecdStart(int q) v0.2
 * Main function on the execd. Does all the data receiving ,etc.
 */
void ExecdStart(int q)
{
    int i, childcount = 0;
    time_t curr_time;
    
    char buffer[OS_MAXSTR + 1];
    char *tmp_msg = NULL;
    char *name;
    char *command;
    char *cmd_args[MAX_ARGS +2];

    /* for select */
    fd_set fdset;
    struct timeval socket_timeout;

    
    /* OSList */
    OSList *timeout_list;
    OSListNode *timeout_node;
    
    
    /* Clearing the buffer */
    memset(buffer, '\0', OS_MAXSTR +1);
    
    
    /* Initializing the cmd arguments */
    for(i = 0; i<= MAX_ARGS +1; i++)
    {
        cmd_args[i] = NULL;
    }
   
    
    /* Creating list for timeout */
    timeout_list = OSList_Create(); 
    if(!timeout_list)
    {
        ErrorExit("%s: Error creating timeout list", ARGV0);
    }
    
   
    /* Receiving loop */
    while(1)
    {
        int timeout_value;
        char **timeout_args;
        timeout_data *timeout_entry;


        /* Cleaning up any child .. */
        while (childcount)
        {
            int wp;
            wp = waitpid((pid_t) -1, NULL, WNOHANG);
            if (wp < 0)
                merror(WAITPID_ERROR, ARGV0);

            /* if = 0, we still need to wait for the child process */
            else if (wp == 0)
                break;
            else
                childcount--;
        }


        /* Getting currently time */
        curr_time = time(0);


        /* Checking if there is any timeout command to execute */
        timeout_node = OSList_GetFirstNode(timeout_list);
        while(timeout_node)
        {
            timeout_data *list_entry;

            list_entry = (timeout_data *)timeout_node->data;

            if((curr_time - list_entry->time_of_addition) > 
                    list_entry->time_to_block)
            {
                /* Deletecurruently node already sets the pointer to next */
                OSList_DeleteCurrentlyNode(timeout_list);

                ExecCmd(list_entry->command);

                FreeTimeoutEntry(list_entry);

                childcount++;
            }

            else
            {
                timeout_node = OSList_GetNextNode(timeout_list);
            }
        }


        /* Setting timeout to EXECD_TIMEOUT */
        socket_timeout.tv_sec = EXECD_TIMEOUT;
        socket_timeout.tv_usec= 0;


        /* Setting FD values */
        FD_ZERO(&fdset);

        FD_SET(q, &fdset);

        /* Adding timeout */
        if(select(q+1, &fdset, NULL, NULL, &socket_timeout) == 0)
        {
            /* timeout gone */
            continue;
        }

        if(!FD_ISSET(q, &fdset))
        {
            merror("%s: Socket error (select). Signal received?",ARGV0);
            continue;
        }

        
        /* Waiting for messages */
        if(recv(q, buffer, OS_MAXSTR, 0) == -1)
        {
            merror(QUEUE_ERROR, ARGV0, EXECQUEUEPATH);
            continue;
        }


        /* Currently time */
        curr_time = time(0);


        /* Allocating memory for the timeout argument */
        timeout_args = calloc(MAX_ARGS+2, sizeof(char *));
        timeout_entry = calloc(1, sizeof(timeout_data));
        if(!timeout_args || !timeout_entry)
        {
            merror(MEM_ERROR, ARGV0);
            continue;    
        }


        merror("received: %s\n", buffer);



        /* Getting application name */
        name = buffer;

        tmp_msg = index(buffer, ' ');
        if(!tmp_msg)
        {
            merror(EXECD_INV_MSG, ARGV0, buffer);
            continue;
        }
        *tmp_msg = '\0';
        tmp_msg++;



        /* Getting the command to execute (valid name) */
        command = GetCommandbyName(name, &timeout_value);
        if(!command)
        {
            ReadExecConfig();
            command = GetCommandbyName(name, &timeout_value);
            if(!command)
            {
                merror(EXEC_INV_NAME, ARGV0, name);
                continue;
            }
        }


        /* Adding initial variables to the cmd_arg and to the timeout cmd */
        cmd_args[0] = command; 
        cmd_args[1] = ADD_ENTRY;
        timeout_args[0] = strdup(command);
        timeout_args[1] = strdup(DELETE_ENTRY);

        cmd_args[2] = NULL;
        timeout_args[2] = NULL;


        /* Getting the arguments */
        i = 2;
        while(i < MAX_ARGS)
        {
            cmd_args[i] = tmp_msg;
            cmd_args[i+1] = NULL;

            tmp_msg = index(tmp_msg, ' ');
            if(!tmp_msg)
            {
                cmd_args[i+1] = NULL;
                break;
            }
            *tmp_msg = '\0';
            tmp_msg++;

            timeout_args[i] = strdup(cmd_args[i]);
            timeout_args[i+1] = NULL;

            i++;
        }


        /* executing command */
        ExecCmd(cmd_args);


        /* Creating the timeout entry */
        timeout_entry->command = timeout_args;
        timeout_entry->time_of_addition = curr_time;
        timeout_entry->time_to_block = timeout_value;


        /* We don't need to add if the timeout_value == 0 */
        if(!timeout_value)
        {
            FreeTimeoutEntry(timeout_entry);
        }        

        /* Adding command to the timeout list */
        else if(!OSList_AddData(timeout_list, timeout_entry))
        {
            FreeTimeoutEntry(timeout_entry);
            merror("%s: Error adding command to the timeout list", ARGV0);
        }

        childcount++;

        /* Some cleanup */
        while(i > 0)
        {
            cmd_args[i] = NULL;
            i--;
        }

        /* Continuing.  */
    }
}

/* EOF */
