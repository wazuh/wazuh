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
#include <sys/socket.h>

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
    char file[OS_MAXSTR +1];
    
    char srcip[IPSIZE +1];
    char *buffer;
    char *cleartext_msg;
    char *tmp_msg;
    
    FILE *fp;

    fd_set fdset;

    struct timeval fdtimeout;

    /* Setting FP to null, before starting */
    fp = NULL;
    
    while(1)
    {
        FD_ZERO(&fdset);
        FD_SET(socket, &fdset);
        
        fdtimeout.tv_sec = 30;
        fdtimeout.tv_usec = 0;

        /* we are only monitoring one socket, so no reason
         * to ISSET
         */
                 
        /* Wait for 30 seconds at a maximum for a reply */
        if(select(socket +1, &fdset, NULL, NULL, &fdtimeout) == 0)
        {
            /* timeout */
            return;
        }
        
        buffer = OS_RecvAllUDP(socket, OS_MAXSTR, srcip, IPSIZE);

        /* Checking if IP is allowed - only the manager */
        if(strcmp(srcip, logr->rip) != 0)
        {
            merror(DENYIP_ERROR,ARGV0,srcip);
            free(buffer);
            continue;
        }
        
        cleartext_msg = ReadSecMSG(&keys, NULL, buffer);
        if(cleartext_msg == NULL)
        {
            free(buffer);
            merror(MSG_ERROR,ARGV0,logr->rip);
            return;
        }

        /* Removing checksum and rand number */
        tmp_msg = r_read(cleartext_msg);
        
        if(!tmp_msg)
        {
            merror("%s: Invalid message from '%s'",ARGV0, logr->rip);
            free(cleartext_msg);
            free(buffer);
            return;
        }
                                                        
        printf("msg is :%s\n",tmp_msg);                                        

        /* Check for commands */
        if(tmp_msg[0] == '#' && tmp_msg[1] == '!' &&
           tmp_msg[2] == '-')
        {
            tmp_msg+=3;

            printf("message is now x:%s\n",tmp_msg);
            
            /* Close any open file pointer if it was being written to */
            if(fp)
            {
                fclose(fp);
                fp = NULL;
            }
            
            if(strncmp(tmp_msg, "up file ", strlen("up file ")) == 0)
            {
                char *validate_file;
                tmp_msg+=strlen("up file ");

                printf("open file: %s\n", tmp_msg);
                
                if((validate_file = index(tmp_msg, '\n')) != NULL)
                {
                    *validate_file = '\0';
                }
                
                if((validate_file = index(tmp_msg, '/')) != NULL)
                {
                    *validate_file = '-';
                }
                
                if((validate_file = index(tmp_msg, '.')) != NULL)
                {
                    *validate_file = '-';
                }
                
                snprintf(file, OS_MAXSTR, "%s/%s", SHAREDCFG_DIR, tmp_msg);

                fp = fopen(file, "w");
                if(!fp)
                {
                    merror("%s: Impossible to open file '%s'", ARGV0, file);
                }
                printf("OPEN!\n");
            }
            
            else if(strncmp(tmp_msg, "close file", strlen("close file")) == 0)
            {
                /* no error */
            }

            else
            {
                merror("%s: Wrong message received.", ARGV0);
            }
        }

        else if(fp)
        {
            printf("writting '%s' to fp\n",tmp_msg);
            fprintf(fp, "%s", tmp_msg);
            fflush(fp);
        }
        
        else
        {
            merror("%s: Invalid message received. No action defined.",ARGV0);
        }
        
        free(cleartext_msg);
        free(buffer);
    }

    if(fp)
        fclose(fp);
        
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
void main_mgr(int socket)
{
    int msg_size;

    char tmp_msg[OS_MAXSTR +1];
    char *crypt_msg;
    char *uname;
    char *shared_files;
    
    
    /* Send the message.
     * Message is going to be the 
     * uname\n checksum file\n checksum file\n 
     */   
    
    /* Getting uname */
    uname = getuname();
    if(!uname)
    {
        uname = strdup("No system info available");
        if(!uname)
        {
            merror(MEM_ERROR,ARGV0);
            return;
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
            free(uname);
            merror(MEM_ERROR,ARGV0);
            return;
        }
    }
    
    printf("shared files is %s\n",shared_files);
    
    /* creating message */
    snprintf(tmp_msg, OS_MAXSTR, "#!-%s\n%s",uname, shared_files);
    
    crypt_msg = CreateSecMSG(&keys, tmp_msg, 0, &msg_size);
    
    if(crypt_msg == NULL)
    {
        free(uname);
        free(shared_files);
        merror(SEC_ERROR,ARGV0);
        return;
    }

    /* Send UDP message */
    if(OS_SendUDPbySize(logr->sock, msg_size, crypt_msg) < 0)
        merror(SEND_ERROR,ARGV0);
                                       
    free(uname);
    free(shared_files);
    free(crypt_msg);

    printf("message sent!\n");
    
    /* Waiting for a reply */
    getreply(socket);
    
    return;
}


/* start_mgr: Start manager thread */
void *start_mgr(void *arg)
{
    struct timeval fp_timeout;
    int *port = (int *)arg;
    int sock;

    /* Bind port to receive commands from server manager */
    if((sock = OS_Bindportudp(*port, NULL)) < 0)
    {
        merror(BIND_ERROR,ARGV0,port);
        return(NULL);
    }


    /* We notify the server every NOTIFY_TIME */
    while(1)
    {
        main_mgr(sock);

        fp_timeout.tv_sec = NOTIFY_TIME -30;
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
