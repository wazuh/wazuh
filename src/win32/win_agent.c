/*    $OSSEC, win_agent.c, v0.1, 2006/04/03, Daniel B. Cid$    */

/* Copyright (C) 2006 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifdef WIN32

#include "shared.h"

#ifndef ARGV0
#define ARGV0 ossec-agent
#endif


/** int WinAgent()
 * Main process of the windows agent
 */
int os_WinAgent()
{
}


/** main(int argc, char **argv)
 * ..
 */
int main(int argc, char **argv)
{

    OS_SetName(ARGV0);

    if(argc > 1)
    {
        if(strcmp(argv[1], "install-service") == 0)
        {
            /* Call install service */
        }
        if(strcmp(argv[1], "uninstall-service") == 0)
        {
            /* Call to uninstall */
        }
        else
        {
            merror("%s: Unknown option: %s", ARGV0, argv[1]);
        }
    }


    /* Read agent config */
    if((binds = ClientConf(DEFAULTCPATH)) == 0)
        ErrorExit(CLIENT_ERROR,ARGV0);

    /* Configuration file not present */
    if(File_DateofChange(cfg) < 0)
        ErrorExit("%s: Configuration file '%s' not found",ARGV0,cfg);


    /* Reading locollector config file */
    LogCollectorConfig(cfg);


    /* Start it */
}


/* SendMSG for windows */
int SendMSG(int queue, char *message, char *locmsg, char loc)
{
    int _ssize;
    char tmpstr[OS_MAXSTR+2];
    char crypt_msg[OS_MAXSTR +2];

    tmpstr[OS_MAXSTR +1] = '\0';
    crypt_msg[OS_MAXSTR +1] = '\0';

    snprintf(tmpstr,OS_MAXSTR,"%c:%s:%s", loc, locmsg, message);

    _ssize = CreateSecMSG(&keys, tmpstr, crypt_msg, 0);


    /* Returns NULL if can't create encrypted message */
    if(_ssize == 0)
    {
        merror(SEC_ERROR,ARGV0);
        return(-1);
    }

    /* Send _ssize of crypt_msg */
    if(OS_SendUDPbySize(logr->sock, _ssize, crypt_msg) < 0)
    {
        merror(SEND_ERROR,ARGV0, "server");
    }
    
    return(0);        
}


/* StartMQ for windows */
int StartMQ(char * path, short int type)
{
    int port;
    
    /* Giving the default port if none is available */
    if((logr->port == NULL) || (port = atoi(logr->port) <= 0))
    {
        port = DEFAULT_SECURE;
    }

    /* Connecting UDP */
    logr->sock = OS_ConnectUDP(port, logr->rip);
    if(logr->sock < 0)
        ErrorExit(CONNS_ERROR,ARGV0,logr->rip);

    path;type;
}

#endif
/* EOF */
