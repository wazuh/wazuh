/* @(#) $Id$ */

/* Copyright (C) 2008 Third Brigade, Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "monitord.h"


int main(int argc, char **argv)
{
    int c, test_config = 0;
    int uid=0,gid=0;
    char *dir  = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;

    /* Initializing global variables */
    mond.a_queue = 0;

    /* Setting the name */
    OS_SetName(ARGV0);
        

    while((c = getopt(argc, argv, "Vdhtu:g:D:c:")) != -1){
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                help(ARGV0);
                break;
            case 'd':
                nowDebug();
                break;
            case 'u':
                if(!optarg)
                    ErrorExit("%s: -u needs an argument",ARGV0);
                user=optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group=optarg;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir=optarg;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 't':
                test_config = 1;    
                break;
            default:
                help(ARGV0);
                break;
        }

    }

    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);

    /*Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
        ErrorExit(USER_ERROR,ARGV0,user,group);


    /* Getting config options */
    mond.day_wait = getDefine_Int("monitord",
                                  "day_wait",
                                  5,240);
    mond.compress = getDefine_Int("monitord",
                                  "compress",
                                  0,1);
    mond.sign = getDefine_Int("monitord","sign",0,1);

    mond.monitor_agents = getDefine_Int("monitord","monitor_agents",0,1);

    mond.agents = NULL;


    /* Exit here if test config is set */
    if(test_config)
        exit(0);

        
    /* Going on daemon mode */
    nowDaemon();
    goDaemon();

    
    /* Privilege separation */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);

    
    /* chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);

    nowChroot();


    
    /* Changing user */        
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);


    debug1(PRIVSEP_MSG,ARGV0,dir,user);



    /* Signal manipulation */
    StartSIG(ARGV0);

    

    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);

    
    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());
    

    /* the real daemon now */	
    Monitord();
    exit(0);
}


/* EOF */
