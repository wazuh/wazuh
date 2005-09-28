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

#include "remoted.h"

#include "os_net/os_net.h"
#include "headers/defs.h"
#include "headers/debug_op.h"
#include "os_crypto/md5/md5_op.h"
#include "error_messages/error_messages.h"

typedef struct _file_sum
{
    int mark;
    char *name;
    os_md5 sum;
}file_sum;

file_sum **f_sum;

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
            merror("%s: Error accessing file '%s'",tmp_dir);
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

/* handleagent: Handle new connections from agent. 
 * If message is just a "I'm alive" message, do not fork.
 * If message is a new one, fork and share configs
 */
void handleagent(int clientsocket, char *srcip)
{
    int i;
    int n;
    int client_size = OS_MAXSTR -1;

    char buf[OS_MAXSTR +1];
    char client_msg[OS_MAXSTR +1];
    char *cleartext_msg;
    char *tmp_msg;
    char *uname;

    /* Null terminating */
    client_msg[0] = '\0';
    client_msg[client_size +1] = '\0';

    /* IP not on the agents list */
    if(CheckAllowedIP(&keys, srcip, NULL) == -1)
    {
        merror(DENYIP_ERROR,ARGV0,srcip);
        close(clientsocket);
        return;
    }

    printf("ip allowed!\n");
    
    /* Reading from client */
    while((n = recv(clientsocket, buf, OS_MAXSTR, 0)) > 0)
    {
        printf("got buf: %d!\n",n);
        
        buf[n] = '\0';
        strncat(client_msg, buf, client_size);
        client_size-= n;

        /* Error in here, message should not be that big */
        if(client_size <= 1)
        {
            merror("%s: Invalid message from client '%s'",ARGV0, srcip);
            close(clientsocket);
            return;
        }
    }

    if(n < 0)
    {
        merror(READ_ERROR,ARGV0);
        close(clientsocket);
        return;
    }

    printf("read message!\n");
    
    /* Decrypting the message */
    cleartext_msg = ReadSecMSG(&keys, srcip, client_msg);
    if(cleartext_msg == NULL)
    {
        merror(MSG_ERROR,ARGV0,srcip);
        close(clientsocket);
        return;
    }

    printf("decrypted!%s\n",cleartext_msg);
    /* Removing checksum and rand number */
    tmp_msg = r_read(cleartext_msg);
    
    printf("message is now:%s\n",tmp_msg);
    
    if(!tmp_msg)
    {
        merror("%s: Invalid message from '%s'",ARGV0, srcip);
        close(clientsocket);
        free(cleartext_msg);
        return;
    }

    /* Get uname */
    uname = tmp_msg;
    tmp_msg = index(tmp_msg,'\n');
    if(!tmp_msg)
    {
        merror("%s: Invalid message from '%s' (uname)",ARGV0, srcip);
        close(clientsocket);
        free(cleartext_msg);
        return;
    }
    *tmp_msg = '\0';
    tmp_msg++;
    
    printf("got uname!:%s\n",uname);
    
    
    /* XXX write uname somewhere */
    
    /* Parse message */ 
    while(*tmp_msg != '\0')
    {
        char *md5;
        char *file;

        md5 = tmp_msg;
        file = tmp_msg;

        tmp_msg = index(tmp_msg, '\n');
        if(!tmp_msg)
        {
            merror("%s: Invalid message from '%s' (index \\n)",ARGV0, srcip);
            break;
        }

        *tmp_msg = '\0';
        tmp_msg++;

        file = index(file, ' ');
        if(!file)
        {
            merror("%s: Invalid message from '%s' (index ' ')",ARGV0, srcip);
            break;
        }

        *file = '\0';
        file++;
    
            
        for(i = 0;;i++)
        {
            if(f_sum[i] == NULL)
                break;
                
            if(strcmp(f_sum[i]->name, file) != 0)
                continue;
            
            if(strcmp(f_sum[i]->sum, md5) != 0)
                f_sum[i]->mark = 1; /* Marked to update */
            
            else
            {
                f_sum[i]->mark = 2;
            }
            break;        
        }
    }

    printf("if fsum\n");
    if(f_sum)
    {
        for(i = 0;;i++)
        {
            if(f_sum[i] == NULL)
                break;

            if((f_sum[i]->mark == 1) ||
                    (f_sum[i]->mark == 0))
            {
            }

            f_sum[i]->mark = 0;        
        }
    }
    
    printf("message is: %s \n",tmp_msg);


    free(cleartext_msg);
    close(clientsocket);

    return; 
}


/* start_mgr: Start manager thread */
void *start_mgr(void *arg)
{
    int sock;
    int clientsock;
    int *port = (int *)arg;
    
    char srcip[16];
    
    time_t ctime;
    printf("Starting manager thread on port %d..\n", *port);


    /* Bind manager port */
    if((sock = OS_Bindporttcp(*port,NULL)) < 0)
        ErrorExit(BIND_ERROR,ARGV0,port);

    
    printf("Bind port \n");

    ctime = time(0);
    c_files();

    /* Receiving connections from now on */
    while(1)
    {
        printf("accept?\n");
        
        if((clientsock = OS_AcceptTCP(sock, srcip, 16)) < 0)
            ErrorExit(CONN_ERROR,ARGV0,port);

        printf("received conn!\n");
        /* Re-readinf files on the shared directory */
        if((time(0) - ctime) > 1200)
        {
            printf("a\n");
            f_files();
            printf("b\n");
            c_files();
            printf("c\n");
        }
        
        printf("handling agent!\n");
        handleagent(clientsock, srcip);    
    }

   printf("done? should't be here\n"); 
        
    
    return NULL;
}

/* EOF */
