/* @(#) $Id: ./src/monitord/main.c, 2011/09/08 dcid Exp $
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
#include "config/config.h"
#include "monitord.h"
#include "os_net/os_net.h"


int main(int argc, char **argv)
{
    int c, test_config = 0, run_foreground = 0;
    int uid=0,gid=0;
    char *dir  = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;
    char *cfg = DEFAULTCPATH;

    /* Initializing global variables */
    mond.a_queue = 0;

    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "Vdhtfu:g:D:c:")) != -1){
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
    mond.smtpserver = NULL;
    mond.emailfrom = NULL;
    mond.emailidsname = NULL;


    c = 0;
    c|= CREPORTS;
    if(ReadConfig(c, cfg, &mond, NULL) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* If we have any reports configured, read smtp/emailfrom */
    if(mond.reports)
    {
        OS_XML xml;
        char *tmpsmtp;

        char *(xml_smtp[])={"ossec_config", "global", "smtp_server", NULL};
        char *(xml_from[])={"ossec_config", "global", "email_from", NULL};
        char *(xml_idsname[])={"ossec_config", "global", "email_idsname", NULL};

        if(OS_ReadXML(cfg, &xml) < 0)
        {
            ErrorExit(CONFIG_ERROR, ARGV0, cfg);
        }

        tmpsmtp = OS_GetOneContentforElement(&xml,xml_smtp);
        mond.emailfrom = OS_GetOneContentforElement(&xml,xml_from);
        mond.emailidsname = OS_GetOneContentforElement(&xml,xml_idsname);

        if(tmpsmtp && mond.emailfrom)
        {
            mond.smtpserver = OS_GetHost(tmpsmtp, 5);
            if(!mond.smtpserver)
            {
                merror(INVALID_SMTP, ARGV0, tmpsmtp);
                if(mond.emailfrom) free(mond.emailfrom);
                mond.emailfrom = NULL;
                merror("%s: Invalid SMTP server.  Disabling email reports.", ARGV0);
            }
        }
        else
        {
            if(tmpsmtp) free(tmpsmtp);
            if(mond.emailfrom) free(mond.emailfrom);

            mond.emailfrom = NULL;

            merror("%s: SMTP server or 'email from' missing. Disabling email reports.", ARGV0);
        }

        OS_ClearXML(&xml);
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
    verbose(STARTUP_MSG, ARGV0, (int)getpid());


    /* the real daemon now */	
    Monitord();
    exit(0);
}


/* EOF */
