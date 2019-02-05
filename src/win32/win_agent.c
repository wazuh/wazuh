/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "client-agent/agentd.h"
#include "logcollector/logcollector.h"
#include "wazuh_modules/wmodules.h"
#include "os_win.h"
#include "os_net/os_net.h"
#include "os_execd/execd.h"
#include "os_crypto/md5/md5_op.h"

#ifndef ARGV0
#define ARGV0 "ossec-agent"
#endif

time_t __win32_curr_time = 0;
time_t __win32_shared_time = 0;
const char *__win32_uname = NULL;
char *__win32_shared = NULL;
HANDLE hMutex;
int win_debug_level;

/** Prototypes **/
int Start_win32_Syscheck();
void send_win32_info(time_t curr_time);


/* Help message */
void agent_help()
{
    printf("\n%s %s %s .\n", __ossec_name, ARGV0, __ossec_version);
    printf("Available options:\n");
    printf("\t/?                This help message.\n");
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
    minfo("Starting syscheckd thread.");

    Start_win32_Syscheck();

    return (NULL);
}

int main(int argc, char **argv)
{
    char *tmpstr;
    char mypath[OS_MAXSTR + 1];
    char myfinalpath[OS_MAXSTR + 1];
    char myfile[OS_MAXSTR + 1];

    /* Set the name */
    OS_SetName(ARGV0);

    /* Find where we are */
    mypath[OS_MAXSTR] = '\0';
    myfinalpath[OS_MAXSTR] = '\0';
    myfile[OS_MAXSTR] = '\0';

    /* mypath is going to be the whole path of the file */
    strncpy(mypath, argv[0], OS_MAXSTR);
    tmpstr = strrchr(mypath, '\\');
    if (tmpstr) {
        /* tmpstr is now the file name */
        *tmpstr = '\0';
        tmpstr++;
        strncpy(myfile, tmpstr, OS_MAXSTR);
    } else {
        strncpy(myfile, argv[0], OS_MAXSTR);
        mypath[0] = '.';
        mypath[1] = '\0';
    }
    chdir(mypath);
    getcwd(mypath, OS_MAXSTR - 1);
    snprintf(myfinalpath, OS_MAXSTR, "\"%s\\%s\"", mypath, myfile);

    if (argc > 1) {
        if (strcmp(argv[1], "install-service") == 0) {
            return (InstallService(myfinalpath));
        } else if (strcmp(argv[1], "uninstall-service") == 0) {
            return (UninstallService());
        } else if (strcmp(argv[1], "start") == 0) {
            return (local_start());
        } else if (strcmp(argv[1], "/?") == 0) {
            agent_help();
        } else if (strcmp(argv[1], "-h") == 0) {
            agent_help();
        } else if (strcmp(argv[1], "help") == 0) {
            agent_help();
        } else {
            merror("Unknown option: %s", argv[1]);
            exit(1);
        }
    }

    /* Start it */
    if (!os_WinMain(argc, argv)) {
        merror_exit("Unable to start WinMain.");
    }

    return (0);
}

/* Locally start (after service/win init) */
int local_start()
{
    int debug_level;
    char *cfg = DEFAULTCPATH;
    WSADATA wsaData;
    DWORD  threadID;
    DWORD  threadID2;
    win_debug_level = getDefine_Int("windows", "debug", 0, 2);

    /* Start agent */
    agt = (agent *)calloc(1, sizeof(agent));
    if (!agt) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    /* Get debug level */
    debug_level = win_debug_level;
    while (debug_level != 0) {
        nowDebug();
        debug_level--;
    }

    /* Configuration file not present */
    if (File_DateofChange(cfg) < 0) {
        merror_exit("Configuration file '%s' not found", cfg);
    }

    /* Start Winsock */
    if (WSAStartup(MAKEWORD(2, 0), &wsaData) != 0) {
        merror_exit("WSAStartup() failed");
    }

    /* Read agent config */
    mdebug1("Reading agent configuration.");
    if (ClientConf(cfg) < 0) {
        merror_exit(CLIENT_ERROR);
    }
    if (agt->notify_time == 0) {
        agt->notify_time = NOTIFY_TIME;
    }
    if (agt->max_time_reconnect_try == 0 ) {
        agt->max_time_reconnect_try = RECONNECT_TIME;
    }
    if (agt->max_time_reconnect_try <= agt->notify_time) {
        agt->max_time_reconnect_try = (agt->notify_time * 3);
        minfo("Max time to reconnect can't be less than notify_time(%d), using notify_time*3 (%d)", agt->notify_time, agt->max_time_reconnect_try);
    }
    minfo("Using notify time: %d and max time to reconnect: %d", agt->notify_time, agt->max_time_reconnect_try);

    /* Read logcollector config file */
    mdebug1("Reading logcollector configuration.");

    /* Init message queue */
    w_msg_hash_queues_init();

    if (LogCollectorConfig(cfg) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    /* Check auth keys */
    if (!OS_CheckKeys()) {
        merror_exit(AG_NOKEYS_EXIT);
    }

    /* If there is no file to monitor, create a clean entry
     * for the mark messages.
     */
    if (logff == NULL) {
        os_calloc(2, sizeof(logreader), logff);
        logff[0].file = NULL;
        logff[0].ffile = NULL;
        logff[0].logformat = NULL;
        logff[0].fp = NULL;
        logff[1].file = NULL;
        logff[1].logformat = NULL;

        minfo(NO_FILE);
    }

    /* No sockets defined */
    if (logsk == NULL) {
        os_calloc(2, sizeof(logsocket), logsk);
        logsk[0].name = NULL;
        logsk[0].location = NULL;
        logsk[0].mode = 0;
        logsk[0].prefix = NULL;
        logsk[1].name = NULL;
        logsk[1].location = NULL;
        logsk[1].mode = 0;
        logsk[1].prefix = NULL;
    }

    /* Read execd config */
    if (!WinExecd_Start()) {
        agt->execdq = -1;
    }

    /* Read keys */
    minfo(ENC_READ);

    OS_ReadKeys(&keys, 1, 0, 0);
    OS_StartCounter(&keys);
    os_write_agent_info(keys.keyentries[0]->name, NULL, keys.keyentries[0]->id, agt->profile);

    /*Set the crypto method for the agent */
    os_set_agent_crypto_method(&keys, agt->crypto_method);

    /* Initialize random numbers */
    srandom(time(0));
    os_random();

    /* Launch rotation thread */
    if (CreateThread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)state_main,
                     NULL,
                     0,
                     (LPDWORD)&threadID) == NULL) {
        merror(THREAD_ERROR);
    }

    /* Socket connection */
    agt->sock = -1;
    StartMQ("", 0);

    /* Start mutex */
    mdebug1("Creating thread mutex.");
    hMutex = CreateMutex(NULL, FALSE, NULL);
    if (hMutex == NULL) {
        merror_exit("Error creating mutex.");
    }
    /* Start buffer thread */
    if (agt->buffer){
        buffer_init();
        if (CreateThread(NULL,
                         0,
                         (LPTHREAD_START_ROUTINE)dispatch_buffer,
                         NULL,
                         0,
                         (LPDWORD)&threadID) == NULL) {
            merror(THREAD_ERROR);
        }
    }else{
        minfo(DISABLED_BUFFER);
    }
    /* Start syscheck thread */
    if (CreateThread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)skthread,
                     NULL,
                     0,
                     (LPDWORD)&threadID) == NULL) {
        merror(THREAD_ERROR);
    }

    /* Launch rotation thread */
    if (CreateThread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)w_rotate_log_thread,
                     NULL,
                     0,
                     (LPDWORD)&threadID) == NULL) {
        merror(THREAD_ERROR);
    }

    /* Check if server is connected */
    os_setwait();
    start_agent(1);
    os_delwait();
    update_status(GA_STATUS_ACTIVE);

    /* Send integrity message for agent configs */
    intcheck_file(cfg, "");
    intcheck_file(OSSEC_DEFINES, "");

    req_init();

    /* Start receiver thread */
    if (CreateThread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)receiver_thread,
                     NULL,
                     0,
                     (LPDWORD)&threadID2) == NULL) {
        merror(THREAD_ERROR);
    }

    /* Start request receiver thread */
    if (CreateThread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)req_receiver,
                     NULL,
                     0,
                     (LPDWORD)&threadID2) == NULL) {
        merror(THREAD_ERROR);
    }

    // Read wodle configuration and start modules

    if (!wm_config() && !wm_check()) {
        wmodule * cur_module;

        for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
            if (CreateThread(NULL,
                            0,
                            (LPTHREAD_START_ROUTINE)cur_module->context->start,
                            cur_module->data,
                            0,
                            (LPDWORD)&threadID2) == NULL) {
                merror(THREAD_ERROR);
            }
        }
    }

    /* Send agent information message */
    send_win32_info(time(0));

    /* Start logcollector -- main process here */
    LogCollectorStart();

    WSACleanup();
    return (0);
}

/* SendMSG for Windows */
int SendMSG(__attribute__((unused)) int queue, const char *message, const char *locmsg, char loc)
{
    time_t cu_time;
    const char *pl;
    char tmpstr[OS_MAXSTR + 2];
    DWORD dwWaitResult;

    tmpstr[OS_MAXSTR + 1] = '\0';

    mdebug2("Attempting to send message to server.");

    os_wait();

    /* Using a mutex to synchronize the writes */
    while (1) {
        dwWaitResult = WaitForSingleObject(hMutex, 1000000L);

        if (dwWaitResult != WAIT_OBJECT_0) {
            switch (dwWaitResult) {
                case WAIT_TIMEOUT:
                    merror("Error waiting mutex (timeout).");
                    sleep(5);
                    continue;
                case WAIT_ABANDONED:
                    merror("Error waiting mutex (abandoned).");
                    return (0);
                default:
                    merror("Error waiting mutex.");
                    return (0);
            }
        } else {
            /* Lock acquired */
            break;
        }
    }   /* end - while for mutex... */

    cu_time = time(0);

#ifndef ONEWAY_ENABLED
    /* Check if the server has responded */
    if ((cu_time - available_server) > agt->notify_time) {
        mdebug1("Sending agent information to server.");
        send_win32_info(cu_time);

        /* Attempt to send message again */
        if ((cu_time - available_server) > agt->notify_time) {
            /* Try again */
            sleep(1);
            send_win32_info(cu_time);
            sleep(1);

            if ((cu_time - available_server) > agt->notify_time) {
                send_win32_info(cu_time);
            }
        }

        /* If we reached here, the server is unavailable for a while */
        if ((cu_time - available_server) > agt->max_time_reconnect_try) {
            int wi = 1;
            mdebug1("More than %d seconds without server response...is server alive? and Is there connection?", agt->max_time_reconnect_try);

            /* Last attempt before going into reconnect mode */
            sleep(1);
            send_win32_info(cu_time);
            if ((cu_time - available_server) > agt->max_time_reconnect_try) {
                sleep(1);
                send_win32_info(cu_time);
                sleep(1);
            }

            /* Check and generate log if unavailable */
            cu_time = time(0);
            if ((cu_time - available_server) > agt->max_time_reconnect_try) {
                int global_sleep = 1;
                int mod_sleep = 12;

                /* If response is not available, set lock and wait for it */
                mwarn(SERVER_UNAV);
                update_status(GA_STATUS_NACTIVE);

                /* Go into reconnect mode */
                while ((cu_time - available_server) > agt->max_time_reconnect_try) {
                    /* Send information to see if server replies */
                    if (agt->sock != -1) {
                        send_win32_info(cu_time);
                    }

                    sleep(wi);
                    cu_time = time(0);

                    if (wi < 20) {
                        wi++;
                    } else {
                        global_sleep++;
                    }

                    /* If we have more than one server, try all */
                    if (wi > 12 && agt->server[1].rip) {
                        int curr_rip = agt->rip_id;
                        minfo("Trying next server IP in line: '%s'.", agt->server[agt->rip_id + 1].rip != NULL ? agt->server[agt->rip_id + 1].rip : agt->server[0].rip);

                        connect_server(agt->rip_id + 1);

                        if (agt->rip_id != curr_rip) {
                            wi = 1;
                        }
                    } else if (global_sleep == 2 || ((global_sleep % mod_sleep) == 0) ||
                               (agt->sock == -1)) {
                        connect_server(agt->rip_id + 1);
                        if (agt->sock == -1) {
                            sleep(wi + global_sleep);
                        } else {
                            sleep(global_sleep);
                        }

                        if (global_sleep > 30) {
                            mod_sleep = 50;
                        }
                    }
                }

                minfo(AG_CONNECTED, agt->server[agt->rip_id].rip, agt->server[agt->rip_id].port, agt->server[agt->rip_id].protocol == UDP_PROTO ? "udp" : "tcp");
                minfo(SERVER_UP);
                update_status(GA_STATUS_ACTIVE);
            }
        }
    }
#else
    if (0) {
    }
#endif

    /* Send notification */
    else if ((cu_time - __win32_curr_time) > agt->notify_time) {
        mdebug1("Sending info to server (ctime2)...");
        send_win32_info(cu_time);
    }

    /* locmsg cannot have the C:, as we use it as delimiter */
    pl = strchr(locmsg, ':');
    if (pl) {
        /* Set pl after the ":" if it exists */
        pl++;
    } else {
        pl = locmsg;
    }

    mdebug2("Sending message to server: '%s'", message);

    snprintf(tmpstr, OS_MAXSTR, "%c:%s:%s", loc, pl, message);

    /* Send events to the manager across the buffer */
    if (!agt->buffer){
        agent_state.msg_count++;
        send_msg(tmpstr, -1);
    }else{
        buffer_append(tmpstr);
    }

    if (!ReleaseMutex(hMutex)) {
        merror("Error releasing mutex.");
    }
    return (0);
}

/* StartMQ for Windows */
int StartMQ(__attribute__((unused)) const char *path, __attribute__((unused)) short int type)
{
    /* Connect to the server */
    connect_server(0);
    return (0);
}

/* Send win32 info to server */
void send_win32_info(time_t curr_time)
{
    char tmp_msg[OS_MAXSTR - OS_HEADER_SIZE + 2];
    char tmp_labels[OS_MAXSTR - OS_HEADER_SIZE] = { '\0' };

    tmp_msg[OS_MAXSTR - OS_HEADER_SIZE + 1] = '\0';

    mdebug1("Sending keep alive message.");

    /* Fix time */
    __win32_curr_time = curr_time;

    /* Get uname */
    if (!__win32_uname) {
        __win32_uname = getuname();
        if (!__win32_uname) {
            merror("Error generating system information.");
            os_strdup("Microsoft Windows - Unknown (unable to get system info)", __win32_uname);
        }
    }

    /* Format labeled data */

    if (!tmp_labels[0] && labels_format(agt->labels, tmp_labels, OS_MAXSTR - OS_HEADER_SIZE) < 0) {
        merror("Too large labeled data.");
        tmp_labels[0] = '\0';
    }

    /* Get shared files list -- every notify_time seconds only */
    if ((__win32_curr_time - __win32_shared_time) > agt->notify_time) {
        if (__win32_shared) {
            free(__win32_shared);
            __win32_shared = NULL;
        }

        __win32_shared_time = __win32_curr_time;
    }

    /* Get shared files */
    if (!__win32_shared) {
        __win32_shared = getsharedfiles();
        if (!__win32_shared) {
            __win32_shared = strdup("\0");
            if (!__win32_shared) {
                merror(MEM_ERROR, errno, strerror(errno));
                return;
            }
        }
    }

    /* Create message */
    if (File_DateofChange(AGENTCONFIGINT) > 0) {
        os_md5 md5sum;
        if (OS_MD5_File(AGENTCONFIGINT, md5sum, OS_TEXT) != 0) {
            snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "#!-%s\n%s%s", __win32_uname, tmp_labels, __win32_shared);
        } else {
            snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "#!-%s / %s\n%s%s", __win32_uname, md5sum, tmp_labels, __win32_shared);
        }
    } else {
        snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "#!-%s\n%s%s", __win32_uname, tmp_labels, __win32_shared);
    }

    /* Create message */
    mdebug2("Sending keep alive: %s", tmp_msg);
    send_msg(tmp_msg, -1);


    update_keepalive(curr_time);

    return;
}

#endif
