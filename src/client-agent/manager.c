/*   $OSSEC, manager.c, v0.1, 2005/09/24, Daniel B. Cid$   */

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
#include <sys/types.h>
#include <dirent.h>
#include <fcntl.h>

#include <errno.h>

#include "os_crypto/md5/md5_op.h"
#include "os_net/os_net.h"
#include "headers/defs.h"
#include "headers/debug_op.h"
#include "headers/file_op.h"
#include "error_messages/error_messages.h"

#include "agentd.h"


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
  


/* getreply: Act based on the message from the server
 */
void getreply(int socket)
{
    int n;

    int client_size = OS_MAXSTR -1;
    char buf[OS_MAXSTR +1];
    char client_msg[OS_MAXSTR +1];
    
    char *cleartext_msg;
    char *tmp_msg;
    
    while((n = recv(socket, buf, OS_MAXSTR, 0)) > 0)
    {
        buf[n] = '\0';
        strncat(client_msg, buf, client_size);
        client_size-= n;

        /* Error in here, message should not be that big */
        if(client_size <= 1)
        {
            merror("%s: Invalid message from server",ARGV0);
            return;
        }
    }

    if(n < 0)
    {
        merror(READ_ERROR,ARGV0);
        return;
    }

    cleartext_msg = ReadSecMSG(&keys, logr->rip, client_msg);
    if(cleartext_msg == NULL)
    {
        merror(MSG_ERROR,ARGV0,logr->rip);
        return;
    }

    /* Removing checksum and rand number */
    tmp_msg = r_read(cleartext_msg);

    if(!tmp_msg)
    {
        merror("%s: Invalid message from '%s'",ARGV0, logr->rip);
        free(cleartext_msg);
        return;
    }

    printf("msg is :%s\n",tmp_msg);

    return;

}


/* getfiles: Return the name of the files in a directory
 */
char *getsharedfiles()
{
    int m_size = 512;

    DIR *dp;

    struct dirent *entry;

    char *ret;
    char *tmp_ret;
    
    os_md5 md5sum;
    
    /* Opening the directory given */
    dp = opendir(SHAREDCFG_DIR);
    if(!dp) 
    {
        merror("%s: Error opening directory: '%s': %s ",
                ARGV0,
                SHAREDCFG_DIR,
                strerror(errno));
        return(NULL);
    }   


    /* we control these files, max size is m_size */
    ret = (char *)calloc(m_size, sizeof(char));
    if(!ret)
    {
        merror(MEM_ERROR);
        return(NULL);
    }
    tmp_ret = ret;

    while((entry = readdir(dp)) != NULL)
    {
        char tmp_dir[256];
        
        /* Just ignore . and ..  */
        if((strcmp(entry->d_name,".") == 0) ||
                (strcmp(entry->d_name,"..") == 0))
            continue;

        snprintf(tmp_dir, 255, "%s/%s", SHAREDCFG_DIR, entry->d_name);

        if(OS_MD5_File(tmp_dir, md5sum) != 0)
        {
            merror("%s: Error accessing file '%s'",tmp_dir);
            continue;
        }
        
        snprintf(tmp_ret, m_size, "%s %s\n", md5sum, entry->d_name);
        
        m_size-=strlen(tmp_ret);

        tmp_ret+=strlen(tmp_ret);
       
        if(*tmp_ret == '\n')
        {
            printf("im \\n lala\n");
            tmp_ret++;
        }
        
    }

    closedir(dp);

    /* If we didn't use ret, free it and return null */
    if(*ret == '\0')
    {
        free(ret);
        ret = NULL;
    }
    
    return(ret);
}

/* main_mgr: main manager thread */
void *main_mgr(void *arg)
{
    int sock;
    int *port = (int *)arg;
    int msg_size;

    
    char tmp_msg[1024];
    char *crypt_msg;
    char *uname;
    char *shared_files;
    
    printf("Starting manager thread on port %d..\n", *port);


    /* Connect to the server */
    if((sock =  OS_ConnectTCP(*port, logr->rip)) < 0)
    {
        merror(CONNS_ERROR, ARGV0, logr->rip);
        return(NULL);
    }
    
    printf("connected \n");

    /* Send the message.
     * Message is going to be the 
     * uname : file checksum : file checksum :
     */   
    
    /* Getting uname */
    uname = getuname();
    if(!uname)
    {
        uname = strdup("No system info available");
        if(!uname)
        {
            close(sock);
            merror(MEM_ERROR,ARGV0);
            return(NULL);
        }
    }
   
    printf("uname is %s\n", uname);
     
    /* get shared files */
    shared_files = getsharedfiles();
    if(!shared_files)
    {
        shared_files = strdup("\0");
        if(!shared_files)
        {
            close(sock);
            free(uname);
            merror(MEM_ERROR,ARGV0);
            return(NULL);
        }
    }
    
    printf("shared files is %s\n",shared_files);
    
    /* creating message */
    snprintf(tmp_msg, 1024, "%s\n%s",uname, shared_files);
    
    crypt_msg = CreateSecMSG(&keys, tmp_msg, 0, &msg_size);
    
    if(crypt_msg == NULL)
    {
        close(sock);
        free(uname);
        free(shared_files);
        merror(SEC_ERROR,ARGV0);
        return(NULL);
    }
   
    /* sending message */
    if(write(sock, crypt_msg, msg_size) < msg_size)
    {
        merror("%s: Error sending message to server (write)",ARGV0);
    }

    printf("message sent!\n");
    
    /* Waiting for a reply */
    getreply(sock);
    
    
    close(sock);
    free(uname);
    free(shared_files);
    free(crypt_msg);
    return(NULL);
}


/* start_mgr: Start manager thread */
void *start_mgr(void *arg)
{
    struct timeval fp_timeout;
    
    /* We notify the server every NOTIFY_TIME */
    while(1)
    {
        main_mgr(arg);

        fp_timeout.tv_sec = NOTIFY_TIME;
        fp_timeout.tv_usec = 0;

        /* Waiting for the select timeout */
        if (select(0, NULL, NULL, NULL, &fp_timeout) < 0)
        {
            merror("%s: Internal error (select).",ARGV0);
            return(NULL);
        }
    }
}

/* EOF */
