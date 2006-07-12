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

time_t __win32_curr_time = 0;


/** Prototypes **/
int Start_win32_Syscheck();


/* Help message */
void agent_help()
{
    printf("\nOSSEC HIDS %s %s .\n", ARGV0, __version);
    printf("Available options:\n");
    printf("\t-h                This help message.\n");
    printf("\thelp              This help message.\n");
    printf("\tinstall-service   Installs as a service\n");
    printf("\tuninstall-service Uninstalls as a service\n");
    printf("\tstart             Manually starts (not from services)\n");
    exit(1);
}

/* syscheck main thread */
void *skthread()
{
    verbose("%s: Starting syscheckd thread.", ARGV0);

    Start_win32_Syscheck();

    return (NULL);
}


/** main(int argc, char **argv)
 * ..
 */
int main(int argc, char **argv)
{
    char *tmpstr;
    char mypath[OS_MAXSTR +1];
    char myfile[OS_MAXSTR +1];

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
        else if(strcmp(argv[1], "uninstall-service") == 0)
        {
            return(UninstallService());
        }
        else if(strcmp(argv[1], "start") == 0)
        {
            return(local_start());
        }
        else if(strcmp(argv[1], "-h") == 0)
        {
            agent_help();
        }
        else if(strcmp(argv[1], "help") == 0)
        {
            agent_help();
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

    return(0);
}


/* Locally starts (after service/win init) */
int local_start()
{
    int binds;
    char *cfg = DEFAULTCPATH;
    WSADATA wsaData;


    /* Starting logr */
    logr = (agent *)calloc(1, sizeof(agent));
    if(!logr)
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }
    logr->port = DEFAULT_SECURE;


    /* Configuration file not present */
    if(File_DateofChange(cfg) < 0)
        ErrorExit("%s: Configuration file '%s' not found",ARGV0,cfg);


    /* Read agent config */
    if((binds = ClientConf(cfg)) == 0)
        ErrorExit(CLIENT_ERROR,ARGV0);


    /* Reading logcollector config file */
    if(LogCollectorConfig(cfg) < 0)
        ErrorExit(CONFIG_ERROR, ARGV0);


    /* Starting syscheck thread */
    {
        DWORD  threadID;

        if(CreateThread(NULL, 
                        0, 
                        (LPTHREAD_START_ROUTINE)skthread, 
                        NULL, 
                        0, 
                        (LPDWORD)&threadID) == NULL)
        {
            merror(THREAD_ERROR, ARGV0);
        }
    }
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
    char *pl;
    char tmpstr[OS_MAXSTR+2];
    char crypt_msg[OS_MAXSTR +2];

    tmpstr[OS_MAXSTR +1] = '\0';
    crypt_msg[OS_MAXSTR +1] = '\0';

    merror("message: %s", message);

    /* locmsg cannot have the C:, as we use it as delimiter */
    pl = strchr(locmsg, ':');
    if(pl)
    {
        /* Setting pl after the ":" if it exists. */
        pl++;
    }
    else
    {
        pl = locmsg;
    }
    
    snprintf(tmpstr,OS_MAXSTR,"%c:%s:%s", loc, pl, message);

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
    /* Connecting UDP */
    logr->sock = OS_ConnectUDP(logr->port, logr->rip);
    if(logr->sock < 0)
        ErrorExit(CONNS_ERROR,ARGV0,logr->rip);

    path[0] = '\0';
    type = 0;

    return(0);
}


/* Send win32 info to server */
void send_win32_info()
{
    int msg_size;
    time_t curr_time;

    curr_time = time(0);

    if((curr_time - __win32_curr_time) > NOTIFY_TIME)
    {
        char tmp_msg[OS_MAXSTR +2];
        char crypt_msg[OS_MAXSTR +2];
        char *myuname;

        tmp_msg[OS_MAXSTR +1] = '\0';
        crypt_msg[OS_MAXSTR +1] = '\0';

        /* fixing time */
        __win32_curr_time = curr_time;

        merror("XXX generating uname.");
        myuname = getuname();
        if(!myuname)
        {
            merror("%s: Error generating system information.", ARGV0);
            return;
        }
        merror("XXX uname is: %s", myuname);

        /* creating message */
        snprintf(tmp_msg, OS_MAXSTR, "#!-%s\n",myuname);

        msg_size = CreateSecMSG(&keys, tmp_msg, crypt_msg, 0);

        if(msg_size == 0)
        {
            free(myuname);
            merror(SEC_ERROR, ARGV0);
            return;
        }

        /* Sending UDP message */
        if(OS_SendUDPbySize(logr->sock, msg_size, crypt_msg) < 0)
        {
            merror(SEND_ERROR, ARGV0, "server");
        }

        free(myuname);
    }

    return;
}

#endif
/* EOF */
