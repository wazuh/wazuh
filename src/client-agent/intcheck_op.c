/* @(#) $Id: ./src/client-agent/intcheck_op.c, 2011/09/08 dcid Exp $
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
#include "agentd.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"



/* intcheck_file
 * Sends integrity checking information about a file to the
 * server.
 */
int intcheck_file(const char *file_name, const char *dir)
{
    struct stat statbuf;

    os_md5 mf_sum;
    os_sha1 sf_sum;

    char newsum[912 +1];

    newsum[0] = '\0';
    newsum[912] = '\0';


    /* Stating the file */
    #ifdef WIN32
    if(stat(file_name, &statbuf) < 0)
    #else
    if(lstat(file_name, &statbuf) < 0)
    #endif
    {
        snprintf(newsum, 911,"%c:%s:-1 %s%s", SYSCHECK_MQ, SYSCHECK,
                                              dir, file_name);
        send_msg(0, newsum);

        return(1);
    }


    /* Generating new checksum */
    #ifdef WIN32
    if(S_ISREG(statbuf.st_mode))
    #else
    if(S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
    #endif
    {
        /* generating md5 of the file */
        if(OS_SHA1_File(file_name, sf_sum) < 0)
        {
            strncpy(sf_sum, "xxx", 4);
        }

        /* generating md5 of the file */
        if(OS_MD5_File(file_name, mf_sum) < 0)
        {
            strncpy(mf_sum, "xxx", 4);
        }
    }


    snprintf(newsum,911,"%c:%s:%d:%d:%d:%d:%s:%s %s%s",
            SYSCHECK_MQ, SYSCHECK,
            (int)statbuf.st_size,
            (int)statbuf.st_mode,
            (int)statbuf.st_uid,
            (int)statbuf.st_gid,
            mf_sum,
            sf_sum, dir, file_name);


    send_msg(0, newsum);
    return(1);
}

/* EOF */
