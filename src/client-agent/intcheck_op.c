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
#include "headers/syscheck_op.h"
#include "os_crypto/md5_sha1_sha256/md5_sha1_sha256_op.h"


/* Send integrity checking information about a file to the server */
int intcheck_file(const char *file_name, const char *dir)
{
    struct stat statbuf;
    os_md5 mf_sum;
    os_sha1 sf_sum;
    os_sha256 sf256_sum;
    char newsum[1172 + 1];

    /* Clean sums */
    strncpy(mf_sum,  "xxx", 4);
    strncpy(sf_sum,  "xxx", 4);
    strncpy(sf256_sum, "xxx", 4);

    newsum[0] = '\0';
    newsum[1172] = '\0';

    /* Stat the file */
#ifdef WIN32
    if (stat(file_name, &statbuf) < 0)
#else
    if (lstat(file_name, &statbuf) < 0)
#endif
    {
        snprintf(newsum, 1172, "%c:%s:-1 %s%s", SYSCHECK_MQ, SYSCHECK,
                 dir, file_name);
        send_msg(newsum, -1);

        return (1);
    }

    /* Generate new checksum */
#ifdef WIN32
    if (S_ISREG(statbuf.st_mode))
#else
    if (S_ISREG(statbuf.st_mode) || S_ISLNK(statbuf.st_mode))
#endif
    {
        if (OS_MD5_SHA1_SHA256_File(file_name, NULL, mf_sum, sf_sum, sf256_sum, OS_BINARY) < 0) {
            strncpy(mf_sum, "n/a", 4);
            strncpy(sf_sum, "n/a", 4);
            strncpy(sf256_sum, "n/a", 4);
        }
    }

#ifdef WIN32
    snprintf(newsum, 1172, "%c:%s:%ld:%d:::%s:%s:%s:%s:%ld:%ld:%s %s%s",
            SYSCHECK_MQ,
            SYSCHECK,
            (long)statbuf.st_size,
            (int)statbuf.st_mode,
            mf_sum,
            sf_sum,
            get_user(file_name, statbuf.st_uid),
            get_group(statbuf.st_gid),
            (long)statbuf.st_mtime,
            (long)statbuf.st_ino,
            sf256_sum,
            dir,
            file_name);
#else
    snprintf(newsum, 1172, "%c:%s:%ld:%d:%d:%d:%s:%s:%s:%s:%ld:%ld:%s %s%s",
            SYSCHECK_MQ,
            SYSCHECK,
            (long)statbuf.st_size,
            (int)statbuf.st_mode,
            (int)statbuf.st_uid,
            (int)statbuf.st_gid,
            mf_sum,
            sf_sum,
            get_user(file_name, statbuf.st_uid),
            get_group(statbuf.st_gid),
            (long)statbuf.st_mtime,
            (long)statbuf.st_ino,
            sf256_sum,
            dir,
            file_name);
#endif
    minfo("~~~ sending integrity for config: %s", newsum);
    send_msg(newsum, -1);
    return (1);
}
