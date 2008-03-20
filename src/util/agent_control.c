/* @(#) $Id$ */

/* Copyright (C) 2008 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#include "addagent/manage_agents.h"
#include "sec.h"


#undef ARGV0
#define ARGV0 "agent_control"


/** help **/
void helpmsg()
{
    printf("\nOSSEC HIDS %s: Control remote agents.\n", ARGV0);
    printf("Available options:\n");
    printf("\t-h          This help message.\n");
    printf("\t-l          List available agents.\n");
    printf("\t-r -a       Runs the integrity/rootkit checking on all agents now.\n");
    printf("\t-r -u <id>  Runs the integrity/rootkit checking on one agent now.\n\n");
    exit(1);
}


/** main **/
int main(int argc, char **argv)
{
    char *dir = DEFAULTDIR;
    char *group = GROUPGLOBAL;
    char *user = USER;
    char *agent_id = NULL;
    int gid = 0;
    int uid = 0;
    int c = 0, restart_syscheck = 0, restart_all_agents = 0, list_agents = 0;
    
    

    /* Setting the name */
    OS_SetName(ARGV0);
        
    
    /* user arguments */
    if(argc < 2)
    {
        helpmsg();
    }


    while((c = getopt(argc, argv, "Vhdlau:")) != -1)
    {
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
            case 'r':
                restart_syscheck = 1;
                break;
            case 'l':
                list_agents = 1;
                break;
            case 'u':
                if(!optarg)
                {
                    merror("%s: -u needs an argument",ARGV0);
                    helpmsg();
                }
                agent_id = optarg;
                break;
            case 'a':
                restart_all_agents = 1;
                break;
            default:
                helpmsg();
                break;
        }

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

    

    /* Listing available agents. */
    if(list_agents == 1)
    {
        printf("\nOSSEC HIDS %s: List of available agents.", 
                ARGV0);
        print_agents();
        printf("\n");
        exit(0);
    }
    


    /* Checking if the provided ID is valid. */
    if(agent_id != NULL) 
    {
        int i;
        keystore keys;

        OS_ReadKeys(&keys);

        i = OS_IsAllowedID(&keys, agent_id);
        if(i < 0)
        {
            printf("\n** Invalid agent id '%s'.\n", agent_id);
            helpmsg();
        }


        /* Valid id. */
        printf("\nOSSEC HIDS %s: Restarting Syscheck/Rootcheck on agent: %s\n",
                ARGV0, agent_id);
    }
   
    return(0);
}


/* EOF */
