/*   $OSSEC, check_rc_dev.c, v0.1, 2005/10/03, Daniel B. Cid$   */

/* Copyright (C) 2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 
#include "shared.h"
#include "rootcheck.h"

int _dev_errors;
int _dev_total;

/** Prototypes **/
int read_dev_dir(char *dir_name);

int read_dev_file(char *file_name)
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
        char op_msg[OS_MAXSTR +1];

        snprintf(op_msg, OS_MAXSTR, "File '%s' present on /dev."
                                    " Possible hidden file.", file_name);
        notify_rk(ALERT_SYSTEM_CRIT, op_msg);

        _dev_errors++;
    }

    return(0);
}

/* read_dir v0.1
 *
 */
int read_dev_dir(char *dir_name)
{
    int i;
    
    DIR *dp;
    
	struct dirent *entry;
    
    /* when will these people learn that dev is not
     * meant to store log files or other kind of texts..
     */
    char *(ignore_dev[]) = {"MAKEDEV","README.MAKEDEV",
                            "MAKEDEV.README", ".udevdb",
                            ".udev.tdb", ".initramfs-tools",
                            "MAKEDEV.local", ".udev", ".initramfs",
    #ifdef SOLARIS                            
                            ".devfsadm_dev.lock",
                            ".devlink_db_lock",
                            ".devlink_db",
                            ".devfsadm_daemon.lock",
                            ".devfsadm_deamon.lock",
                            ".devfsadm_synch_door",
                            ".zone_reg_door",
    #elif Darwin
                            "fd",                        
    #endif
                            NULL};    
    
    
    if((dir_name == NULL)||(strlen(dir_name) > PATH_MAX))
    {
        merror("%s: Invalid directory given",ARGV0);
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
             
        snprintf(f_name, PATH_MAX +1, "%s/%s",dir_name, entry->d_name);
        
        read_dev_file(f_name);

    }

    closedir(dp);
    
    return(0);
}


/*  check_rc_dev: v0.1
 *
 */
void check_rc_dev(char *basedir)
{
    char file_path[OS_MAXSTR +1];
    
    _dev_total = 0, _dev_errors = 0;

    debug1("%s: DEBUG: Starting on check_rc_dev", ARGV0);

    snprintf(file_path, OS_MAXSTR, "%s/dev", basedir);

    read_dev_dir(file_path);

    if(_dev_errors == 0)
    {
        char op_msg[OS_MAXSTR +1];
        snprintf(op_msg, OS_MAXSTR, "No problem detected on the /dev "
                                    "directory. Analyzed %d files", 
                                    _dev_total);
        notify_rk(ALERT_OK, op_msg);
    }
    
    return;
}

/* EOF */
