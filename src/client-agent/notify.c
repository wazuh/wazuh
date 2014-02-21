/* @(#) $Id: ./src/client-agent/notify.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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

time_t g_saved_time = 0;


char *rand_keepalive_str2(char *dst, int size)
{
    static const char text[] = "abcdefghijklmnopqrstuvwxyz"
                               "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                               "0123456789"
                               "!@#$%^&*()_+-=;'[],./?";
    int i, len = rand() % (size - 1);
    for ( i = 0; i < len; ++i )
    {
        dst[i] = text[rand() % (sizeof text - 1)];
    }
    dst[i] = '\0';
    return dst;
}

/* getfiles: Return the name of the files in a directory
 */
char *getsharedfiles()
{
    int m_size = 512;

    char *ret;

    os_md5 md5sum;


    if(OS_MD5_File(SHAREDCFG_FILE, md5sum) != 0)
    {
        md5sum[0] = 'x';
        md5sum[1] = 'x';
        md5sum[1] = '\0';
    }


    /* we control these files, max size is m_size */
    ret = (char *)calloc(m_size +1, sizeof(char));
    if(!ret)
    {
        merror(MEM_ERROR, ARGV0);
        return(NULL);
    }


    snprintf(ret, m_size, "%s merged.mg\n", md5sum);


    return(ret);
}

#ifndef WIN32

/* run_notify: Send periodically notification to server */
void run_notify()
{
    char keep_alive_random[1024];
    char tmp_msg[OS_SIZE_1024 +1];
    char *uname;
    char *shared_files;
    os_md5 md5sum;


    keep_alive_random[0] = '\0';

    time_t curr_time;

    curr_time = time(0);


    #ifndef ONEWAY
    /* Check if the server has responded */
    if((curr_time - available_server) > agt->max_time_reconnect_try)
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
    #endif


    /* Check if time has elapsed */
    if((curr_time - g_saved_time) < agt->notify_time)
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

    rand_keepalive_str2(keep_alive_random, 700);


    /* creating message */
    if((File_DateofChange(AGENTCONFIGINT) > 0 ) &&
       (OS_MD5_File(AGENTCONFIGINT, md5sum) == 0))
    {
        snprintf(tmp_msg, OS_SIZE_1024, "#!-%s / %s\n%s\n%s",
                 uname, md5sum, shared_files, keep_alive_random);
    }
    else
    {
        snprintf(tmp_msg, OS_SIZE_1024, "#!-%s\n%s\n%s",
                 uname, shared_files, keep_alive_random);
    }


    /* Sending status message */
    send_msg(0, tmp_msg);


    free(uname);
    free(shared_files);

    return;
}
#endif


/* EOF */
