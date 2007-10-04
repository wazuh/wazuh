/* @(#) $Id$ */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"

#include "os_crypto/md5/md5_op.h"
#include "os_net/os_net.h"
#include "agentd.h"

time_t g_saved_time = 0;



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
        merror(MEM_ERROR, ARGV0);
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
            merror("%s: Error accessing file '%s': %s",ARGV0, 
                                                 tmp_dir, strerror(errno));
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

#ifndef WIN32

/* run_notify: Send periodically notification to server */
void run_notify()
{
    char tmp_msg[OS_SIZE_1024 +1];
    char *uname;
    char *shared_files;

    time_t curr_time;

    curr_time = time(0);


    /* Check if the server has responded */
    if((curr_time - available_server) > (3*NOTIFY_TIME))
    {
        /* If response is not available, set lock and
         * wait for it.
         */
        verbose(SERVER_UNAV, ARGV0);
        os_setwait();

        /* Send sync message */
        start_agent(0);

        verbose(SERVER_UP, ARGV0);
        os_delwait();
    }


    /* Check if time has elapsed */
    if((curr_time - g_saved_time) < (NOTIFY_TIME - 120))
    {
        return;
    }
    g_saved_time = curr_time;
    
    debug1("%s: DEBUG: Sending agent notification.", ARGV0);


    /* Send the message.
     * Message is going to be the 
     * uname\n checksum file\n checksum file\n 
     */   

    /* Getting uname */
    uname = getuname();
    if(!uname)
    {
        merror(MEM_ERROR,ARGV0);
        return;
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
    snprintf(tmp_msg, OS_SIZE_1024, "#!-%s\n%s",uname, shared_files);


    /* Sending status message */
    send_msg(0, tmp_msg);


    free(uname);
    free(shared_files);

    return;
}
#endif


/* EOF */
