/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */



#include "manage_agents.h"

/* print banner */
void print_banner()
{
    printf("\n");
    printf(BANNER, __name, __version);

    #ifdef CLIENT
    printf(BANNER_CLIENT);
    #else
    printf(BANNER_OPT);
    #endif

    return;
}


/* Clean shutdown on kill */
void manage_shutdown()
{
    /* Checking if restart message is necessary */
    if(restart_necessary)
    {
        printf(MUST_RESTART);
    }
    else
    {
        printf("\n");
    }
    printf(EXIT);

    exit(0);
}


/** main **/
int main(int argc, char **argv)
{
    char *user_msg;
    
    #ifndef WIN32
    char *dir = DEFAULTDIR;
    char *group = GROUPGLOBAL;
    int gid;
    #endif
    
    if(argv[argc -1]){}    
    

    /* Setting the name */
    OS_SetName(ARGV0);
        
   
    /* Getting currently time */
    time1 = time(0);
    restart_necessary = 0;
    
    
    #ifndef WIN32 
    /* Getting the group name */
    gid = Privsep_GetGroup(group);
    if(gid < 0)
    {
	    ErrorExit(USER_ERROR, ARGV0, "", group);
    }
	
    
    /* Setting the group */
    if(Privsep_SetGroup(gid) < 0)
    {
	    ErrorExit(SETGID_ERROR, ARGV0, group);
    }
    
    
    /* Chrooting to the default directory */
    if(Privsep_Chroot(dir) < 0)
    {
        ErrorExit(CHROOT_ERROR, ARGV0, dir);
    }


    /* Inside chroot now */
    nowChroot();


    /* Starting signal handler */
    StartSIG2(ARGV0, manage_shutdown);
    #endif


    /* Little shell */
    while(1)
    {
        int leave_s = 0;
        print_banner();
   
        user_msg = read_from_user();
        
        /* All the allowed actions */
        switch(user_msg[0])
        {
            case 'A':
            case 'a':
                add_agent();
                break;
            case 'e':
            case 'E':
                k_extract();
                break;
            case 'i':
            case 'I':
                k_import();
                break;    
            case 'l':
            case 'L':
                list_agents();
                break;    
            case 'r':
            case 'R':
                remove_agent();
                break;
            case 'q':
            case 'Q':
                leave_s = 1;
                break;
	        case 'V':
		        print_version();   
		        break;
            default:    
                printf("\n ** Invalid Action ** \n\n");
                break;            
        }

        if(leave_s)
        {
            break;       
        }
        
        continue;
        
    }

    /* Checking if restart message is necessary */
    if(restart_necessary)
    {
        printf(MUST_RESTART);
    }
    else
    {
        printf("\n");
    }
    printf(EXIT);
    
    return(0);
}


/* EOF */
