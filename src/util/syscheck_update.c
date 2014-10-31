/* @(#) $Id: ./src/util/syscheck_update.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "addagent/manage_agents.h"
#include "sec.h"

#undef ARGV0
#define ARGV0 "syscheck_update"

static void helpmsg(void) __attribute__((noreturn));

/** help **/
static void helpmsg()
{
    printf("\nOSSEC HIDS %s: Updates (clears) the integrity check database.\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h       This help message.\n");
    printf("\t-l       List available agents.\n");
    printf("\t-a       Update (clear) syscheck database for all agents.\n");
    printf("\t-u <id>  Update (clear) syscheck database for a specific agent.\n");
    printf("\t-u local Update (clear) syscheck database locally.\n\n");
    exit(1);
}

/** main **/
int main(int argc, char **argv)
{
    const char *dir = DEFAULTDIR;
    const char *group = GROUPGLOBAL;
    const char *user = USER;
    gid_t gid;
    uid_t uid;


    /* Setting the name */
    OS_SetName(ARGV0);


    /* user arguments */
    if(argc < 2)
    {
        helpmsg();
    }

    /* Getting the group name */
    gid = Privsep_GetGroup(group);
    uid = Privsep_GetUser(user);
    if(uid == (uid_t)-1 || gid == (gid_t)-1)
    {
	    ErrorExit(USER_ERROR, ARGV0, user, group);
    }


    /* Setting the group */
    if(Privsep_SetGroup(gid) < 0)
    {
	    ErrorExit(SETGID_ERROR,ARGV0, group, errno, strerror(errno));
    }


    /* Chrooting to the default directory */
    if(Privsep_Chroot(dir) < 0)
    {
        ErrorExit(CHROOT_ERROR, ARGV0, dir, errno, strerror(errno));
    }


    /* Inside chroot now */
    nowChroot();


    /* Setting the user */
    if(Privsep_SetUser(uid) < 0)
    {
        ErrorExit(SETUID_ERROR, ARGV0, user, errno, strerror(errno));
    }

    /* User options */
    if(strcmp(argv[1], "-h") == 0)
    {
        helpmsg();
    }
    else if(strcmp(argv[1], "-l") == 0)
    {
        printf("\nOSSEC HIDS %s: Updates the integrity check database.",
                                 ARGV0);
        print_agents(0, 0, 0);
        printf("\n");
        exit(0);
    }
    else if(strcmp(argv[1], "-u") == 0)
    {
        if(argc != 3)
        {
            printf("\n** Option -u requires an extra argument\n");
            helpmsg();
        }
    }
    else if(strcmp(argv[1], "-a") == 0)
    {
        DIR *sys_dir;
        struct dirent *entry;

        sys_dir = opendir(SYSCHECK_DIR);
        if(!sys_dir)
        {
            ErrorExit("%s: Unable to open: '%s'", ARGV0, SYSCHECK_DIR);
        }

        while((entry = readdir(sys_dir)) != NULL)
        {
            FILE *fp;
            char full_path[OS_MAXSTR +1];

            /* Do not even attempt to delete . and .. :) */
            if((strcmp(entry->d_name,".") == 0)||
               (strcmp(entry->d_name,"..") == 0))
            {
                continue;
            }

            snprintf(full_path, OS_MAXSTR,"%s/%s", SYSCHECK_DIR, entry->d_name);

            fp = fopen(full_path, "w");
            if(fp)
            {
                fclose(fp);
            }
            if(entry->d_name[0] == '.')
            {
                unlink(full_path);
            }
        }

        closedir(sys_dir);
        printf("\n** Integrity check database updated.\n\n");
        exit(0);
    }
    else
    {
        printf("\n** Invalid option '%s'.\n", argv[1]);
        helpmsg();
    }


    /* local */
    if(strcmp(argv[2],"local") == 0)
    {
        char final_dir[1024];
        FILE *fp;
        snprintf(final_dir, 1020, "/%s/syscheck", SYSCHECK_DIR);

        fp = fopen(final_dir, "w");
        if(fp)
        {
            fclose(fp);
        }
        unlink(final_dir);


        /* Deleting cpt file */
        snprintf(final_dir, 1020, "/%s/.syscheck.cpt", SYSCHECK_DIR);

        fp = fopen(final_dir, "w");
        if(fp)
        {
            fclose(fp);
        }
        /* unlink(final_dir); */
    }

    /* external agents */
    else
    {
        int i;
        keystore keys;

        OS_ReadKeys(&keys);

        i = OS_IsAllowedID(&keys, argv[2]);
        if(i < 0)
        {
            printf("\n** Invalid agent id '%s'.\n", argv[2]);
            helpmsg();
        }

        /* Deleting syscheck */
        delete_syscheck(keys.keyentries[i]->name,keys.keyentries[i]->ip->ip,0);
    }

    printf("\n** Integrity check database updated.\n\n");
    return(0);
}


/* EOF */
