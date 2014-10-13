/* @(#) $Id: ./src/rootcheck/check_rc_dev.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WIN32
#include "shared.h"
#include "rootcheck.h"

static int _dev_errors;
static int _dev_total;

/** Prototypes **/
static int read_dev_file(const char *file_name);
static int read_dev_dir(const char *dir_name);

static int read_dev_file(const char *file_name)
{
    struct stat statbuf;

    if(lstat(file_name, &statbuf) < 0)
    {
        return(-1);
    }

    if(S_ISDIR(statbuf.st_mode))
    {
        #ifdef DEBUG
        verbose("%s: Reading dir: %s\n",ARGV0, file_name);
        #endif

        return(read_dev_dir(file_name));
    }

    else if(S_ISREG(statbuf.st_mode))
    {
        char op_msg[OS_SIZE_1024 +1];

        snprintf(op_msg, OS_SIZE_1024, "File '%s' present on /dev."
                                    " Possible hidden file.", file_name);
        notify_rk(ALERT_SYSTEM_CRIT, op_msg);

        _dev_errors++;
    }

    return(0);
}

/* read_dir v0.1
 *
 */
static int read_dev_dir(const char *dir_name)
{
    int i;

    DIR *dp;

	struct dirent *entry;

    /* when will these people learn that dev is not
     * meant to store log files or other kind of texts..
     */
    const char *(ignore_dev[]) = {"MAKEDEV","README.MAKEDEV",
                            "MAKEDEV.README", ".udevdb",
                            ".udev.tdb", ".initramfs-tools",
                            "MAKEDEV.local", ".udev", ".initramfs",
                            "oprofile","fd","cgroup",
    #ifdef SOLARIS
                            ".devfsadm_dev.lock",
                            ".devlink_db_lock",
                            ".devlink_db",
                            ".devfsadm_daemon.lock",
                            ".devfsadm_deamon.lock",
                            ".devfsadm_synch_door",
                            ".zone_reg_door",
    #endif
                            NULL};


    /* Full path ignore */
    const char *(ignore_dev_full_path[]) = {"/dev/shm/sysconfig",
                                      "/dev/bus/usb/.usbfs",
                                      "/dev/shm",
                                      "/dev/gpmctl",
                                      NULL};

    if((dir_name == NULL)||(strlen(dir_name) > PATH_MAX))
    {
        merror("%s: Invalid directory given.",ARGV0);
        return(-1);
    }

    /* Opening the directory given */
    dp = opendir(dir_name);
	if(!dp)
    {
        return(-1);
    }

    while((entry = readdir(dp)) != NULL)
    {
        char f_name[PATH_MAX +2];

        /* Just ignore . and ..  */
        if((strcmp(entry->d_name,".") == 0) ||
           (strcmp(entry->d_name,"..") == 0))
            continue;

        _dev_total++;

        /* Do not look for the ignored files */
        for(i = 0;ignore_dev[i] != NULL;i++)
        {
            if(strcmp(ignore_dev[i], entry->d_name) == 0)
                break;
        }

        if(ignore_dev[i] != NULL)
            continue;

        f_name[PATH_MAX +1] = '\0';
        snprintf(f_name, PATH_MAX +1, "%s/%s",dir_name, entry->d_name);


        /* Do not look for the full ignored files */
        for(i = 0;ignore_dev_full_path[i] != NULL;i++)
        {
            if(strcmp(ignore_dev_full_path[i], f_name) == 0)
                break;
        }


        /* Checking against the full path. */
        if(ignore_dev_full_path[i] != NULL)
        {
            continue;
        }


        read_dev_file(f_name);

    }

    closedir(dp);

    return(0);
}


/*  check_rc_dev: v0.1
 *
 */
void check_rc_dev(const char *basedir)
{
    char file_path[OS_SIZE_1024 +1];

    _dev_total = 0, _dev_errors = 0;

    debug1("%s: DEBUG: Starting on check_rc_dev", ARGV0);

    snprintf(file_path, OS_SIZE_1024, "%s/dev", basedir);

    read_dev_dir(file_path);

    if(_dev_errors == 0)
    {
        char op_msg[OS_SIZE_1024 +1];
        snprintf(op_msg, OS_SIZE_1024, "No problem detected on the /dev "
                                    "directory. Analyzed %d files",
                                    _dev_total);
        notify_rk(ALERT_OK, op_msg);
    }

    return;
}

/* EOF */

#else
/* Windows */
void check_rc_dev(char *basedir)
{
    return;
}
#endif
