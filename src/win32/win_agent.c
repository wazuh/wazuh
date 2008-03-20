/* @(#) $Id$ */

/* Copyright (C) 2003-2007 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation.
 *
 * License details at the LICENSE file included with OSSEC or 
 * online at: http://www.ossec.net/en/licensing.html
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
HANDLE hMutex;


/** Prototypes **/
int Start_win32_Syscheck();
void send_win32_info(time_t curr_time);


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
            exit(1);
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
    int debug_level;
    char *cfg = DEFAULTCPATH;
    WSADATA wsaData;
    DWORD  threadID;
    DWORD  threadID2;


    /* Starting logr */
    logr = (agent *)calloc(1, sizeof(agent));
    if(!logr)
    {
        ErrorExit(MEM_ERROR, ARGV0);
    }
    logr->port = DEFAULT_SECURE;


    /* Getting debug level */
    debug_level = getDefine_Int("windows","debug", 0, 2);
    while(debug_level != 0)
    {
        nowDebug();
        debug_level--;
    }
    
    
    
    /* Configuration file not present */
    if(File_DateofChange(cfg) < 0)
        ErrorExit("%s: Configuration file '%s' not found",ARGV0,cfg);


    /* Starting Winsock */
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0)
    {
        ErrorExit("%s: WSAStartup() failed", ARGV0);
    }
                                

    /* Read agent config */
    debug1("%s: DEBUG: Reading agent configuration.", ARGV0);
    if(ClientConf(cfg) < 0)
    {
        ErrorExit(CLIENT_ERROR,ARGV0);
    }


    /* Reading logcollector config file */
    debug1("%s: DEBUG: Reading logcollector configuration.", ARGV0);
    if(LogCollectorConfig(cfg) < 0)
    {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }


    /* Checking auth keys */
    if(!OS_CheckKeys())
    {
        ErrorExit(AG_NOKEYS_EXIT, ARGV0);
    }
                                


    /* If there is not file to monitor, create a clean entry
     * for the mark messages.
     */
    if(logff == NULL)
    {
        os_calloc(2, sizeof(logreader), logff);
        logff[0].file = NULL;
        logff[0].ffile = NULL;
        logff[0].logformat = NULL;
        logff[0].fp = NULL;
        logff[1].file = NULL;
        logff[1].logformat = NULL;

        merror(NO_FILE, ARGV0);
    }

    
    /* Reading the private keys  */
    debug1("%s: DEBUG: Reading private keys.", ARGV0);
    OS_ReadKeys(&keys);
    OS_StartCounter(&keys);


    /* Initial random numbers */
    srandom(time(0));
    random();


    /* Socket connection */
    StartMQ(NULL, 0);


    /* Starting mutex */
    debug1("%s: DEBUG: Creating thread mutex.", ARGV0);
    hMutex = CreateMutex(NULL, FALSE, NULL);
    if(hMutex == NULL)
    {
        ErrorExit("%s: Error creating mutex.", ARGV0);
    }


    /* Starting syscheck thread */
    if(CreateThread(NULL, 
                    0, 
                    (LPTHREAD_START_ROUTINE)skthread, 
                    NULL, 
                    0, 
                    (LPDWORD)&threadID) == NULL)
    {
        merror(THREAD_ERROR, ARGV0);
    }

    

    /* Checking if server is connected */
    os_setwait();
        
    start_agent(1);
            
    os_delwait();


    /* Sending integrity message for agent configs */
    intcheck_file(cfg, "");
    intcheck_file(OSSEC_DEFINES, "");
                
                    

    /* Starting receiver thread */
    if(CreateThread(NULL, 
                    0, 
                    (LPTHREAD_START_ROUTINE)receiver_thread, 
                    NULL, 
                    0, 
                    (LPDWORD)&threadID2) == NULL)
    {
        merror(THREAD_ERROR, ARGV0);
    }
    
    
    /* Sending agent information message */
    send_win32_info(time(0));
    
    
    /* Startting logcollector -- main process here */
    LogCollectorStart();

    WSACleanup();
    return(0);
}


/* SendMSG for windows */
int SendMSG(int queue, char *message, char *locmsg, char loc)
{
    int _ssize;
    
    time_t cu_time;
    
    char *pl;
    char tmpstr[OS_MAXSTR+2];
    char crypt_msg[OS_MAXSTR +2];
    
    DWORD dwWaitResult; 

    tmpstr[OS_MAXSTR +1] = '\0';
    crypt_msg[OS_MAXSTR +1] = '\0';

    debug2("%s: DEBUG: Attempting to send message to server.", ARGV0);
    
    /* Using a mutex to synchronize the writes */
    while(1)
    {
        dwWaitResult = WaitForSingleObject(hMutex, 10000L);

        if(dwWaitResult != WAIT_OBJECT_0) 
        {
            switch(dwWaitResult)
            {
                case WAIT_TIMEOUT:
                    merror("%s: Error waiting mutex (timeout).", ARGV0);
                    sleep(5);
                    continue;
                case WAIT_ABANDONED:
                    merror("%s: Error waiting mutex (abandoned).", ARGV0);
                    return(0);
                default:    
                    merror("%s: Error waiting mutex.", ARGV0);    
                    return(0);
            }
        }
        else
        {
            /* Lock acquired */
            break;
        }
    }


    cu_time = time(0);
    

    /* Check if the server has responded */
    if((cu_time - available_server) > (NOTIFY_TIME - 120))
    {
        send_win32_info(cu_time);

        if((cu_time - available_server) > (3 * NOTIFY_TIME))
        {
            int wi = 1;

            /* If response is not available, set lock and
             * wait for it.
             */
            verbose(SERVER_UNAV, ARGV0);

            cu_time = time(0);
            while((cu_time - available_server) > (3*NOTIFY_TIME))
            {
                /* Sending information to see if server replies */
                send_win32_info(cu_time);

                sleep(wi);
                cu_time = time(0);
                wi++;


                /* If we have more than one server, try all. */
                if((logr->rip[1]) && (wi > 5))
                {
                    int curr_rip = logr->rip_id;
                    merror("%s: INFO: Trying next server ip in the line: '%s'.", 
                            ARGV0,
                            logr->rip[logr->rip_id + 1] != NULL?
                            logr->rip[logr->rip_id + 1]:
                            logr->rip[0]);
                    
                    connect_server(logr->rip_id +1);

                    if(logr->rip_id != curr_rip)
                    {
                        wi = 1;
                    }
                }
            }

            verbose(SERVER_UP, ARGV0);
        }
    }
    
    /* Send notification */
    else if((cu_time - __win32_curr_time) > (NOTIFY_TIME - 150))
    {
        send_win32_info(cu_time);
    }


    
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

    
    debug2("%s: DEBUG: Sending message to server: '%s'", ARGV0, message);
    
    snprintf(tmpstr,OS_MAXSTR,"%c:%s:%s", loc, pl, message);

    _ssize = CreateSecMSG(&keys, tmpstr, crypt_msg, 0);


    /* Returns NULL if can't create encrypted message */
    if(_ssize == 0)
    {
        merror(SEC_ERROR,ARGV0);
        if(!ReleaseMutex(hMutex))
        {
            merror("%s: Error releasing mutex.", ARGV0);        
        }
        
        return(-1);
    }

    /* Send _ssize of crypt_msg */
    if(OS_SendUDPbySize(logr->sock, _ssize, crypt_msg) < 0)
    {
        merror(SEND_ERROR,ARGV0, "server");
    }

    if(!ReleaseMutex(hMutex))
    {
        merror("%s: Error releasing mutex.", ARGV0);
    }
    return(0);        
}


/* StartMQ for windows */
int StartMQ(char * path, short int type)
{
    /* Connecting to the server. */
    connect_server(0);
    
    if((path == NULL) && (type == 0))
    {
        return(0);
    }
    
    return(0);
}


/* Send win32 info to server */
void send_win32_info(time_t curr_time)
{
    int msg_size;
    char tmp_msg[OS_MAXSTR +2];
    char crypt_msg[OS_MAXSTR +2];
    char *myuname;
    char *shared_files;

    tmp_msg[OS_MAXSTR +1] = '\0';
    crypt_msg[OS_MAXSTR +1] = '\0';


    debug1("%s: DEBUG: Sending keep alive message.", ARGV0);


    /* fixing time */
    __win32_curr_time = curr_time;

    myuname = getuname();
    if(!myuname)
    {
        merror("%s: Error generating system information.", ARGV0);
        return;
    }

    /* get shared files */
    shared_files = getsharedfiles();
    if(!shared_files)
    {
        shared_files = strdup("\0");
        if(!shared_files)
        {
            free(myuname);
            merror(MEM_ERROR,ARGV0);
            return;
        }
    }

    /* creating message */
    snprintf(tmp_msg, OS_SIZE_1024, "#!-%s\n%s",myuname, shared_files);
    debug1("%s: DEBUG: Sending keep alive: %s", ARGV0, tmp_msg);

    msg_size = CreateSecMSG(&keys, tmp_msg, crypt_msg, 0);

    if(msg_size == 0)
    {
        free(myuname);
        free(shared_files);
        merror(SEC_ERROR, ARGV0);
        return;
    }

    /* Sending UDP message */
    if(OS_SendUDPbySize(logr->sock, msg_size, crypt_msg) < 0)
    {
        merror(SEND_ERROR, ARGV0, "server");
    }

    free(myuname);
    free(shared_files);

    return;
}

#endif
/* EOF */
