/* @(#) $Id: ./src/agentlessd/main.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#include "shared.h"
#include "agentlessd.h"
#include "config/config.h"

static void help_agentlessd(void) __attribute__((noreturn));

/* print help statement */
static void help_agentlessd()
{
    print_header();
    print_out("  %s: -[Vhdtf] [-u user] [-g group] [-c config] [-D dir]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -u <user>   User to run as (default: %s)", USER);
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out("    -D <dir>    Directory to chroot into (default: %s)", DEFAULTDIR);
    print_out(" ");
    exit(1);
}

int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    uid_t uid;
    gid_t gid;
    const char *dir  = DEFAULTDIR;
    const char *user = USER;
    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULTCPATH;


    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1){
        switch(c){
            case 'V':
                print_version();
                break;
            case 'h':
                help_agentlessd();
                break;
            case 'd':
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
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
                break;
            case 'c':
                if(!optarg)
                    ErrorExit("%s: -c needs an argument",ARGV0);
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_agentlessd();
                break;
        }

    }


    /* Starting daemon */
    debug1(STARTED_MSG,ARGV0);


    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if(uid == (uid_t)-1 || gid == (gid_t)-1)
        ErrorExit(USER_ERROR,ARGV0,user,group);


    /* Reading config. */
    c = 0;
    c|= CAGENTLESS;
    lessdc.entries = NULL;
    lessdc.queue = 0;

    if(ReadConfig(c, cfg, &lessdc, NULL) < 0)
    {
        ErrorExit(XML_INV_AGENTLESS, ARGV0);
    }


    /* Exit here if test config is set */
    if(test_config)
        exit(0);


    /* Going on daemon mode */
    if(!run_foreground)
    {
        nowDaemon();
        goDaemonLight();
    }

    if(chdir(dir) == -1)
    {
        ErrorExit(CHDIR_ERROR, ARGV0, dir, errno, strerror(errno));
    }


    /* Exiting if not configured. */
    if(!lessdc.entries)
    {
        verbose("%s: INFO: Not configured. Exiting.", ARGV0);
        exit(0);
    }


    /* Privilege separation */
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group, errno, strerror(errno));


    /* Changing user */
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user, errno, strerror(errno));


    debug1(PRIVSEP_MSG,ARGV0,dir,user);



    /* Signal manipulation */
    StartSIG(ARGV0);



    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR,ARGV0);


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());


    /* the real daemon now */
    Agentlessd();
}


/* EOF */
