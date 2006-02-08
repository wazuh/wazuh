/*   $OSSEC, syscheck_update.c, v0.2, 2006/02/07, Daniel B. Cid$   */

/* Copyright (C) 2005,2006 Daniel B. Cid <dcid@ossec.net>
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

/** help **/
void helpmsg()
{
    printf("\nOSSEC HIDS %s: Updates the integrity check database.\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h       This help message.\n");
    printf("\t-l       List available agents.\n");
    printf("\t-u <id>  Update syscheck database for a specific agent.\n");
    printf("\t-u local Update syscheck database locally.\n\n");
    exit(1);
}


/** main **/
int main(int argc, char **argv)
{
    char *dir = DEFAULTDIR;
    char *group = GROUPGLOBAL;
    char *user = USER;
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
    if(gid < 0)
    {
	    ErrorExit(USER_ERROR,user,group);
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
    else if(strcmp(argv[1], "-l") == 0)
    {
        printf("\nOSSEC HIDS %s: Updates the integrity check database.", 
                                 ARGV0);
        print_agents();
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
        snprintf(final_dir, 1020, "/%s/syscheck",
                                  "queue/syscheck");  
        
        fp = fopen(final_dir, "w");
        if(fp)
        {
            fprintf(fp, "aaaaaaaaabbccdd");
            printf("ok: '%s'\n", final_dir);
            fclose(fp);
        }
        else
        {
            printf("error!!!!\n");
        }
        //unlink(final_dir);
    }

    /* external agents */
    else
    {
        int i;
        char final_dir[1024];
        FILE *fp;
        keystruct keys;

        ReadKeys(&keys);

        i = IsAllowedID(&keys, argv[2]);
        if(i < 0)
        {
            printf("\n** Invalid agent id '%s'.\n", argv[2]);
            helpmsg();
        }
        
        snprintf(final_dir, 1020, "/%s/%s->syscheck",
                                    "queue/syscheck",
                                    keys.ips[i]);  
       
        fp = fopen(final_dir, "w");
        if(fp)
            fclose(fp);
        //unlink(final_dir);
    }
   
    printf("\n** Integrity check database updated\n\n"); 
    return(0);
}


/* EOF */
