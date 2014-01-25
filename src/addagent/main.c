/* @(#) $Id: ./src/addagent/main.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */



#include "manage_agents.h"
#include <stdlib.h>

/** help **/
void helpmsg()
{
    printf("\nOSSEC HIDS %s: Manage agents.\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h          This help message.\n");
    printf("\t-V          Display OSSEC version.\n");
    printf("\t-l          List available agents.\n");
    printf("\t-e <id>     Extracts key for an agent (Manager only).\n");
    printf("\t-i <id>     Import authentication key (Agent only).\n");
    printf("\t-f <file>   Bulk generate client keys from file. (Manager only).\n");
    printf("\t            <file> contains lines in IP,NAME format.\n\n");
    exit(1);
}


/* print banner */
void print_banner()
{
    printf("\n");
    printf(BANNER, __ossec_name, __version);

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

    int c = 0, cmdlist = 0;
    char *cmdexport = NULL;
    char *cmdimport = NULL;
    char *cmdbulk = NULL;

    #ifndef WIN32
    char *dir = DEFAULTDIR;
    char *group = GROUPGLOBAL;
    int gid;
    #endif


    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "Vhle:i:f:")) != -1){
        switch(c){
	        case 'V':
		        print_version();
		        break;
            case 'h':
                helpmsg();
                break;
            case 'd':
                nowDebug();
                break;
            case 'e':
                #ifdef CLIENT
                ErrorExit("%s: You can't export keys on an agent", ARGV0);
                #endif
                if(!optarg)
                    ErrorExit("%s: -e needs an argument",ARGV0);
                cmdexport = optarg;
                break;
            case 'i':
                #ifndef CLIENT
                ErrorExit("%s: You can't import keys on the manager.", ARGV0);
                #endif
                if(!optarg)
                    ErrorExit("%s: -i needs an argument",ARGV0);
                cmdimport = optarg;
                break;
            case 'f':
                #ifdef CLIENT
                ErrorExit("%s: You can't bulk generate keys on an agent.", ARGV0);
                #endif
                if(!optarg)
                    ErrorExit("%s: -f needs an argument",ARGV0);
                cmdbulk = optarg;
                printf("Bulk load file: %s\n", cmdbulk);
                break;
            case 'l':
                cmdlist = 1;
                break;
            default:
                helpmsg();
                break;
        }

    }



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


    if(cmdlist == 1)
    {
        list_agents(cmdlist);
        exit(0);
    }
    else if(cmdimport)
    {
        k_import(cmdimport);
        exit(0);
    }
    else if(cmdexport)
    {
        k_extract(cmdexport);
        exit(0);
    }
    else if(cmdbulk)
    {
        k_bulkload(cmdbulk);
        exit(0);
    }



    /* Little shell */
    while(1)
    {
        int leave_s = 0;
        print_banner();

        /* Get ACTION from the environment. If ACTION is specified,
         * we must set leave_s = 1 to ensure that the loop will end */
        user_msg = getenv("OSSEC_ACTION");
        if (user_msg == NULL) {
          user_msg = read_from_user();
        }
        else{
          leave_s = 1;
        }

        /* All the allowed actions */
        switch(user_msg[0])
        {
            case 'A':
            case 'a':
                add_agent();
                break;
            case 'e':
            case 'E':
                k_extract(NULL);
                break;
            case 'i':
            case 'I':
                k_import(NULL);
                break;
            case 'l':
            case 'L':
                list_agents(0);
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
