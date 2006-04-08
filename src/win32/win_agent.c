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
#include "agentd.h"
#include "logcollector.h"
#include "os_win.h"
#include "os_net/os_net.h"

#ifndef ARGV0
#define ARGV0 "ossec-agent"
#endif



/** main(int argc, char **argv)
 * ..
 */
int main(int argc, char **argv)
{
    int binds;
    char *cfg = DEFAULTCPATH;
    char *tmpstr;
    char mypath[OS_MAXSTR +1];
    char myfile[OS_MAXSTR +1];
    WSADATA wsaData;


    /* Setting the name */
    OS_SetName(ARGV0);


    /* Find where I'm */
    mypath[OS_MAXSTR] = '\0';
    myfile[OS_MAXSTR] = '\0';
    
    /* mypath is going to be the whole path of the file */
    strncpy(mypath, argv[0], OS_MAXSTR);
    tmpstr = strrchr(mypath, '\\');
    if(tmpstr)
    {
        /* tmpstr is now the file name */
        *tmpstr = '\0';
        tmpstr++;
        strncpy(myfile, tmpstr, OS_MAXSTR);
    }
    else
    {
        strncpy(myfile, argv[0], OS_MAXSTR);
        mypath[0] = '.';
        mypath[1] = '\0';
    }
    chdir(mypath);
    getcwd(mypath, OS_MAXSTR -1);
    strncat(mypath, "\\", OS_MAXSTR - (strlen(mypath) + 2));
    strncat(mypath, myfile, OS_MAXSTR - (strlen(mypath) + 2));
    
     
    if(argc > 1)
    {
        if(strcmp(argv[1], "install-service") == 0)
        {
            return(InstallService(mypath));
            
        }
        if(strcmp(argv[1], "uninstall-service") == 0)
        {
            return(UninstallService());
        }
        else
        {
            merror("%s: Unknown option: %s", ARGV0, argv[1]);
        }
    }


    /* Start it */
    if(!os_WinMain(argc, argv))
    {
        ErrorExit("%s: Unable to start WinMain.", ARGV0);
    }


    /* Starting logr */
    logr = (agent *)calloc(1, sizeof(agent));
    if(!logr)
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }
                                
    
    /* Read agent config */
    if((binds = ClientConf(DEFAULTCPATH)) == 0)
        ErrorExit(CLIENT_ERROR,ARGV0);


    /* Configuration file not present */
    if(File_DateofChange(cfg) < 0)
        ErrorExit("%s: Configuration file '%s' not found",ARGV0,cfg);


    /* Reading logcollector config file */
    LogCollectorConfig(cfg);


    /* Reading the private keys  */
    ReadKeys(&keys);


    /* Initial random numbers */
    srand(time(0));
    rand();

                            
    /* Starting winsock stuff */
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
    {
        ErrorExit("%s: WSAStartup() failed", ARGV0);
    }

    /* Socket connection */
    {
        /* Bogus code not used */
        char pp[2]; int tt;
        StartMQ(pp, tt);
    }
    

    /* Startting logcollector -- main process here */
    LogCollectorStart();
    
    WSACleanup();
    return(0);
}


/* SendMSG for windows */
int SendMSG(int queue, char *message, char *locmsg, char loc)
{
    int _ssize;
    char tmpstr[OS_MAXSTR+2];
    char crypt_msg[OS_MAXSTR +2];

    tmpstr[OS_MAXSTR +1] = '\0';
    crypt_msg[OS_MAXSTR +1] = '\0';

    merror("message: %s", message);
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

    path[0] = '\0';
    type = 0;

    return(0);
}

#endif
/* EOF */
