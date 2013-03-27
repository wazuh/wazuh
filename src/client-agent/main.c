/* @(#) $Id: ./src/client-agent/main.c, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net
 */


/* agent daemon.
 */


#include "shared.h"
#include "agentd.h"

#ifndef ARGV0
   #define ARGV0 "ossec-agentd"
#endif





/* main, v0.2, 2005/11/09
 */
int main(int argc, char **argv)
{
    int c = 0;
    int test_config = 0;

    char *dir = DEFAULTDIR;
    char *user = USER;
    char *group = GROUPGLOBAL;

    int uid = 0;
    int gid = 0;


    /* Setting the name */
    OS_SetName(ARGV0);


    while((c = getopt(argc, argv, "Vtdhu:g:D:")) != -1){
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
                user = optarg;
                break;
            case 'g':
                if(!optarg)
                    ErrorExit("%s: -g needs an argument",ARGV0);
                group = optarg;
                break;		
            case 't':
                test_config = 1;
                break;
            case 'D':
                if(!optarg)
                    ErrorExit("%s: -D needs an argument",ARGV0);
                dir = optarg;
                break;
        }
    }

    debug1(STARTED_MSG, ARGV0);

    logr = (agent *)calloc(1, sizeof(agent));
    if(!logr)
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }


    /* Reading config */
    if(ClientConf(DEFAULTCPATH) < 0)
    {
        ErrorExit(CLIENT_ERROR,ARGV0);
    }

    if(!logr->rip)
    {
        merror(AG_INV_IP, ARGV0);
        ErrorExit(CLIENT_ERROR,ARGV0);
    }


    /* Checking auth keys */
    if(!OS_CheckKeys())
    {
        ErrorExit(AG_NOKEYS_EXIT, ARGV0);
    }


    /* Check if the user/group given are valid */
    uid = Privsep_GetUser(user);
    gid = Privsep_GetGroup(group);
    if((uid < 0)||(gid < 0))
    {
        ErrorExit(USER_ERROR,ARGV0,user,group);
    }



    /* Exit if test config */
    if(test_config)
        exit(0);


    /* Starting the signal manipulation */
    StartSIG(ARGV0);	


    /* Agentd Start */
    AgentdStart(dir, uid, gid, user, group);


    return(0);
}

/* EOF */
