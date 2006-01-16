/*   $OSSEC, notify.c, v0.2, 2005/11/09, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"

#include "os_crypto/md5/md5_op.h"
#include "os_net/os_net.h"

#include "agentd.h"


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
        closedir(dp);
        merror(MEM_ERROR);
        return(NULL);
    }
    tmp_ret = ret;

    while((entry = readdir(dp)) != NULL)
    {
        char tmp_dir[256];
        
        /* Just ignore . and ..  */
        if((strcmp(entry->d_name,".") == 0) ||
           (strcmp(entry->d_name,"..") == 0) ||
           (entry->d_name[0] == '.'))
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
            tmp_ret++;
        
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



/* run_notify: Send periodically notification to server */
void run_notify()
{
    int msg_size;

    char tmp_msg[OS_MAXSTR +1];
    char crypt_msg[OS_MAXSTR +1];
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
    
    
    /* creating message */
    snprintf(tmp_msg, OS_MAXSTR, "#!-%s\n%s",uname, shared_files);
    
    msg_size = CreateSecMSG(&keys, tmp_msg, crypt_msg, 0);
    
    if(msg_size == 0)
    {
        free(uname);
        free(shared_files);
        merror(SEC_ERROR,ARGV0);
        return;
    }

    /* Send UDP message */
    if(OS_SendUDPbySize(logr->sock, msg_size, crypt_msg) < 0)
    {
        merror(SEND_ERROR,ARGV0, "server");
    }
    
    free(uname);
    free(shared_files);

    return;
}



/* notify_mgr: Start notify thread */
void *notify_thread(void *none)
{
    time_t curr_time;
    time_t saved_time;

    saved_time = curr_time = time(0);
    run_notify();
    
    /* We notify the server every NOTIFY_TIME - 30 */
    while(1)
    {

        if(pthread_mutex_lock(&notify_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(NULL);
        }

        /* Time not elapsed.. */
        curr_time = time(0);
        if((curr_time - saved_time) < NOTIFY_TIME)
        {
            pthread_cond_wait(&notify_cond, &notify_mutex);
        }
        else
        {
            saved_time = curr_time;
            run_notify();
        }

        /* Unlocking mutex */
        if(pthread_mutex_unlock(&notify_mutex) != 0)
        {
            merror(MUTEX_ERROR, ARGV0);
            return(NULL);
        }

    }
    
    return(NULL);
}



/* EOF */
