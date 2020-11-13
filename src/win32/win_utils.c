/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32
#include "shared.h"
#include "client-agent/agentd.h"
#include "logcollector/logcollector.h"
#include "os_execd/execd.h"
#include "wazuh_modules/wmodules.h"

HANDLE hMutex;
int win_debug_level;

/** Prototypes **/
int Start_win32_Syscheck();

/* syscheck main thread */
void *skthread()
{

    Start_win32_Syscheck();

    return (NULL);
}

/* Locally start (after service/win init) */
int local_start()
{
    int rc;
    char *cfg = DEFAULTCPATH;
    WSADATA wsaData;
    DWORD  threadID;
    DWORD  threadID2;
    win_debug_level = getDefine_Int("windows", "debug", 0, 2);

    /* Get debug level */
    int debug_level = win_debug_level;
    while (debug_level != 0) {
        nowDebug();
        debug_level--;
    }

    /* Initialize logging module*/
    w_logging_init();

    /* Start agent */
    os_calloc(1, sizeof(agent), agt);

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

    if (!Validate_Address(agt->server)){
        merror(AG_INV_MNGIP, agt->server[0].rip);
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

    // Resolve hostnames
    rc = 0;
    while (rc < agt->server_count) {
        if (OS_IsValidIP(agt->server[rc].rip, NULL) != 1) {
            mdebug2("Resolving server hostname: %s", agt->server[rc].rip);
            resolveHostname(&agt->server[rc].rip, 5);
            mdebug2("Server hostname resolved: %s", agt->server[rc].rip);
        }
        rc++;
    }

    /* Read logcollector config file */
    mdebug1("Reading logcollector configuration.");

    /* Init message queue */
    w_msg_hash_queues_init();

    if (LogCollectorConfig(cfg) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    if(agt->enrollment_cfg && agt->enrollment_cfg->enabled) {
        // If autoenrollment is enabled, we will avoid exit if there is no valid key
        OS_PassEmptyKeyfile();
    } else {
        /* Check auth keys */
        if (!OS_CheckKeys()) {
            merror_exit(AG_NOKEYS_EXIT);
        }
    }
    /* Read keys */
    minfo(ENC_READ);
    OS_ReadKeys(&keys, 1, 0);

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

    /* Initialize sender */
    sender_init();

    /* Initialize random numbers */
    srandom(time(0));
    os_random();

    // Initialize children pool
    wm_children_pool_init();

    /* state_main thread */
    w_create_thread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)state_main,
                     NULL,
                     0,
                     (LPDWORD)&threadID);

    /* Socket connection */
    agt->sock = -1;

    /* Start mutex */
    mdebug1("Creating thread mutex.");
    hMutex = CreateMutex(NULL, FALSE, NULL);
    if (hMutex == NULL) {
        merror_exit("Error creating mutex.");
    }
    /* Start buffer thread */
    if (agt->buffer){
        buffer_init();
        w_create_thread(NULL,
                         0,
                         (LPTHREAD_START_ROUTINE)dispatch_buffer,
                         NULL,
                         0,
                         (LPDWORD)&threadID);
    }else{
        minfo(DISABLED_BUFFER);
    }
    /* Start syscheck thread */
    w_create_thread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)skthread,
                     NULL,
                     0,
                     (LPDWORD)&threadID);

    /* Launch rotation thread */
    int rotate_log = getDefine_Int("monitord", "rotate_log", 0, 1);
    if (rotate_log) {
        w_create_thread(NULL,
                        0,
                        (LPTHREAD_START_ROUTINE)w_rotate_log_thread,
                        NULL,
                        0,
                        (LPDWORD)&threadID);
    }

    /* Check if server is connected */
    os_setwait();
    start_agent(1);
    os_delwait();
    update_status(GA_STATUS_ACTIVE);

    req_init();

    /* Start receiver thread */
    w_create_thread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)receiver_thread,
                     NULL,
                     0,
                     (LPDWORD)&threadID2);

    /* Start request receiver thread */
    w_create_thread(NULL,
                     0,
                     (LPTHREAD_START_ROUTINE)req_receiver,
                     NULL,
                     0,
                     (LPDWORD)&threadID2);

    // Read wodle configuration and start modules

    if (!wm_config() && !wm_check()) {
        wmodule * cur_module;

        for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
            w_create_thread(NULL,
                            0,
                            (LPTHREAD_START_ROUTINE)cur_module->context->start,
                            cur_module->data,
                            0,
                            (LPDWORD)&threadID2);
        }
    }

    /* Start logcollector -- main process here */
    LogCollectorStart();

    WSACleanup();
    return (0);
}

/* SendMSG for Windows */
int SendMSG(__attribute__((unused)) int queue, const char *message, const char *locmsg, char loc)
{
    const char *pl;
    char tmpstr[OS_MAXSTR + 2];
    DWORD dwWaitResult;

    tmpstr[OS_MAXSTR + 1] = '\0';

    os_wait();

    /* Using a mutex to synchronize the writes */
    while (1) {
        dwWaitResult = WaitForSingleObject(hMutex, 1000000L);

        if (dwWaitResult != WAIT_OBJECT_0) {
            switch (dwWaitResult) {
                case WAIT_TIMEOUT:
                    mdebug2("Sending mutex timeout.");
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

    /* locmsg cannot have the C:, as we use it as delimiter */
    pl = strchr(locmsg, ':');
    if (pl) {
        /* Set pl after the ":" if it exists */
        pl++;
    } else {
        pl = locmsg;
    }

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
int StartMQ(__attribute__((unused)) const char *path, __attribute__((unused)) short int type, __attribute__((unused)) short int n_tries)
{
    return (0);
}

char *get_agent_ip()
{
    typedef char* (*CallFunc)(PIP_ADAPTER_ADDRESSES pCurrAddresses, int ID, char * timestamp);

    char *agent_ip = NULL;
    int min_metric = INT_MAX;

    static HMODULE sys_library = NULL;
    static CallFunc _get_network_vista = NULL;


    ULONG flags = (checkVista() ? (GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_INCLUDE_GATEWAYS) : 0);

    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 0;
    ULONG Iterations = 0;
    DWORD dwRetVal = 0;

    PIP_ADAPTER_ADDRESSES pCurrAddresses = NULL;

    PIP_ADAPTER_INFO AdapterInfo = NULL;

    /* Allocate a 15 KB buffer to start with */
    outBufLen = WORKING_BUFFER_SIZE;

    do {
        pAddresses = (IP_ADAPTER_ADDRESSES *) win_alloc(outBufLen);

        if (pAddresses == NULL) {
            mterror_exit(WM_SYS_LOGTAG, "Memory allocation failed for IP_ADAPTER_ADDRESSES struct.");
        }

        dwRetVal = GetAdaptersAddresses(AF_UNSPEC, flags, NULL, pAddresses, &outBufLen);

        if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
            win_free(pAddresses);
            pAddresses = NULL;
        } else {
            break;
        }

        Iterations++;
    } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));

    if (dwRetVal == NO_ERROR) {
        if (!checkVista()) {
            /* Retrieve additional data from IPv4 interfaces using GetAdaptersInfo() (under XP) */
            Iterations = 0;
            outBufLen = WORKING_BUFFER_SIZE;

            do {
                AdapterInfo = (IP_ADAPTER_INFO *) win_alloc(outBufLen);

                if (AdapterInfo == NULL) {
                    mterror_exit(WM_SYS_LOGTAG, "Memory allocation failed for IP_ADAPTER_INFO struct.");
                }

                dwRetVal = GetAdaptersInfo(AdapterInfo, &outBufLen);

                if (dwRetVal == ERROR_BUFFER_OVERFLOW) {
                    win_free(AdapterInfo);
                    AdapterInfo = NULL;
                } else {
                    break;
                }

                Iterations++;
            } while ((dwRetVal == ERROR_BUFFER_OVERFLOW) && (Iterations < MAX_TRIES));
        } else {
            if (!sys_library) {
                sys_library = LoadLibrary("syscollector_win_ext.dll");
            }

            if (sys_library && !_get_network_vista) {
                if (_get_network_vista = (CallFunc)GetProcAddress(sys_library, "get_network_vista"), !_get_network_vista) {
                    dwRetVal = GetLastError();
                    mterror(WM_SYS_LOGTAG, "Unable to access 'get_network_vista' on syscollector_win_ext.dll.");
                    goto end;
                }
            }
        }

        if (dwRetVal == NO_ERROR) {
            pCurrAddresses = pAddresses;
            while (pCurrAddresses) {
                char *string;
                /* Ignore Loopback interface */
                if (pCurrAddresses->IfType == IF_TYPE_SOFTWARE_LOOPBACK) {
                    pCurrAddresses = pCurrAddresses->Next;
                    continue;
                }

                /* Ignore interfaces without valid IPv4 indexes */
                if (pCurrAddresses->IfIndex == 0) {
                    pCurrAddresses = pCurrAddresses->Next;
                    continue;
                }

                if (checkVista()) {
                    if (!sys_library) {
                        merror("Could not load library 'syscollector_win_ext.dll'");
                        goto end;
                    }

                    /* Call function get_network_vista() in syscollector_win_ext.dll */
                    string = _get_network_vista(pCurrAddresses, 0, NULL);
                } else {
                    /* Call function get_network_xp() */
                    string = get_network_xp(pCurrAddresses, AdapterInfo, 0, NULL);
                }

                const char *jsonErrPtr;
                cJSON *object = cJSON_ParseWithOpts(string, &jsonErrPtr, 0);
                cJSON *iface = cJSON_GetObjectItem(object, "iface");
                cJSON *ipv4 = cJSON_GetObjectItem(iface, "IPv4");
                if(ipv4){
                    cJSON * gateway = cJSON_GetObjectItem(ipv4, "gateway");
                    if (gateway) {
                        if(checkVista()){
                            cJSON * metric = cJSON_GetObjectItem(ipv4, "metric");
                            if (metric && metric->valueint < min_metric) {
                                cJSON *addresses = cJSON_GetObjectItem(ipv4, "address");
                                cJSON *address = cJSON_GetArrayItem(addresses,0);
                                free(agent_ip);
                                os_strdup(address->valuestring, agent_ip);
                                min_metric = metric->valueint;
                            }
                        }
                        else{
                            cJSON *addresses = cJSON_GetObjectItem(ipv4, "address");
                            cJSON *address = cJSON_GetArrayItem(addresses,0);
                            free(agent_ip);
                            os_strdup(address->valuestring, agent_ip);
                            free(string);
                            cJSON_Delete(object);
                            break;
                        }
                    }
                }
                free(string);
                cJSON_Delete(object);
                pCurrAddresses = pCurrAddresses->Next;
            }
        }
    }

end:

    if (pAddresses) {
        win_free((HLOCAL)pAddresses);
    }

    return agent_ip;
}

#endif
