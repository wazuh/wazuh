/* @(#) $Id: ./src/os_csyslogd/main.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or
 * online at: http://www.ossec.net/en/licensing.html
 */


#include "csyslogd.h"



int main(int argc, char **argv)
{
    int c, test_config = 0,run_foreground = 0;
    int uid = 0,gid = 0;

    /* Using MAILUSER (read only) */
    char *dir  = DEFAULTDIR;
    char *user = MAILUSER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;


    /* Database Structure */
    SyslogConfig **syslog_config = NULL;


    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "vVdhtfu:g:D:c:")) != -1){
        switch(c){
            case 'V':
                print_version();
                break;
            case 'v':
                print_version();
                break;
            case 'h':
                help(ARGV0);
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
                help(ARGV0);
                break;
        }

    }


    /* Starting daemon */
    debug1(STARTED_MSG, ARGV0);


    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
    {
        ErrorExit(USER_ERROR, ARGV0, user, group);
    }


    /* Reading configuration */
    syslog_config = OS_ReadSyslogConf(test_config, cfg, syslog_config);


    /* Getting servers hostname */
    memset(__shost, '\0', 512);
    if(gethostname(__shost, 512 -1) != 0)
    {
        ErrorExit("%s: ERROR: gethostname() failed", ARGV0);
    }
    else
    {
        char *ltmp;

        /* Remove domain part if available */
        ltmp = strchr(__shost, '.');
        if(ltmp)
            *ltmp = '\0';
    }


    /* Exit here if test config is set */
    if(test_config)
        exit(0);


    if (!run_foreground)
    {
        /* Going on daemon mode */
        nowDaemon();
        goDaemon();
    }



    /* Not configured */
    if(!syslog_config || !syslog_config[0])
    {
        verbose("%s: INFO: Remote syslog server not configured. "
                "Clean exit.", ARGV0);
        exit(0);
    }



    /* Privilege separation */	
    if(Privsep_SetGroup(gid) < 0)
        ErrorExit(SETGID_ERROR,ARGV0,group);


    /* chrooting */
    if(Privsep_Chroot(dir) < 0)
        ErrorExit(CHROOT_ERROR,ARGV0,dir);


    /* Now on chroot */
    nowChroot();



    /* Changing user */
    if(Privsep_SetUser(uid) < 0)
        ErrorExit(SETUID_ERROR,ARGV0,user);


    /* Basic start up completed. */
    debug1(PRIVSEP_MSG,ARGV0,dir,user);


    /* Signal manipulation */
    StartSIG(ARGV0);


    /* Creating PID files */
    if(CreatePID(ARGV0, getpid()) < 0)
        ErrorExit(PID_ERROR, ARGV0);


    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());


    /* the real daemon now */	
    OS_CSyslogD(syslog_config);
    exit(0);
}


/* EOF */
