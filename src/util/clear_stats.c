/* @(#) $Id: ./src/util/clear_stats.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


/* This tool will clear the project statistics */

#include "shared.h"

#undef ARGV0
#define ARGV0 "clear_stats"

static void helpmsg(void) __attribute__((noreturn));

/** help **/
static void helpmsg()
{
    printf("\nOSSEC HIDS %s: Clear the events stats (averages).\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h       This help message.\n");
    printf("\t-a       Clear all the stats (averages).\n");
    printf("\t-d       Clear the daily averages.\n");
    printf("\t-w       Clear the weekly averages.\n\n");
    exit(1);
}


/** main **/
int main(int argc, char **argv)
{
    int clear_daily = 0;
    int clear_weekly = 0;

    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *user = USER;
    int gid;
    int uid;


    /* Setting the name */
    OS_SetName(ARGV0);


    /* user arguments */
    if(argc != 2)
    {
        helpmsg();
    }

    /* Getting the group name */
    gid = Privsep_GetGroup(group);
    uid = Privsep_GetUser(user);
    if(gid < 0)
    {
	    ErrorExit(USER_ERROR, ARGV0, user, group);
    }


    /* Setting the group */
    if(Privsep_SetGroup(gid) < 0)
    {
	    ErrorExit(SETGID_ERROR,ARGV0, group);
    }


    /* Chrooting to the default directory */
    if(Privsep_Chroot(dir) < 0)
    {
        ErrorExit(CHROOT_ERROR, ARGV0, dir);
    }


    /* Inside chroot now */
    nowChroot();


    /* Setting the user */
    if(Privsep_SetUser(uid) < 0)
    {
        ErrorExit(SETUID_ERROR, ARGV0, user);
    }

    /* User options */
    if(strcmp(argv[1], "-h") == 0)
    {
        helpmsg();
    }
    else if(strcmp(argv[1], "-a") == 0)
    {
        clear_daily = 1;
        clear_weekly = 1;
    }
    else if(strcmp(argv[1], "-d") == 0)
    {
        clear_daily = 1;
    }
    else if(strcmp(argv[1], "-w") == 0)
    {
        clear_weekly = 1;
    }
    else
    {
        printf("\n** Invalid option '%s'.\n", argv[1]);
        helpmsg();
    }


    /* Clear daily files */
    if(clear_daily)
    {
        const char *daily_dir = STATQUEUE;
        DIR *daily;
        struct dirent *entry;

        daily = opendir(daily_dir);
        if(!daily)
        {
            ErrorExit("%s: Unable to open: '%s'", ARGV0, daily_dir);
        }

        while((entry = readdir(daily)) != NULL)
        {
            char full_path[OS_MAXSTR +1];

            /* Do not even attempt to delete . and .. :) */
            if((strcmp(entry->d_name,".") == 0)||
               (strcmp(entry->d_name,"..") == 0))
            {
                continue;
            }

            /* Remove file */
            full_path[OS_MAXSTR] = '\0';
            snprintf(full_path, OS_MAXSTR, "%s/%s", daily_dir, entry->d_name);
            unlink(full_path);
        }

        closedir(daily);
    }


    /* Clear weekly averages */
    if(clear_weekly)
    {
        int i = 0;
        while(i <= 6)
        {
            const char *daily_dir = STATWQUEUE;
            char dir_path[OS_MAXSTR +1];
            DIR *daily;
            struct dirent *entry;

            snprintf(dir_path, OS_MAXSTR, "%s/%d", daily_dir, i);
            daily = opendir(dir_path);
            if(!daily)
            {
                ErrorExit("%s: Unable to open: '%s' (no stats)",
                           ARGV0, dir_path);
            }

            while((entry = readdir(daily)) != NULL)
            {
                char full_path[OS_MAXSTR +1];

                /* Do not even attempt to delete . and .. :) */
                if((strcmp(entry->d_name,".") == 0)||
                        (strcmp(entry->d_name,"..") == 0))
                {
                    continue;
                }

                /* Remove file */
                full_path[OS_MAXSTR] = '\0';
                snprintf(full_path, OS_MAXSTR, "%s/%s", dir_path,
                                                        entry->d_name);
                unlink(full_path);
            }

            i++;
            closedir(daily);
        }
    }

    printf("\n** Internal stats clear.\n\n");
    return(0);
}


/* EOF */
