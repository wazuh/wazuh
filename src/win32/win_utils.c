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
#include "sysInfo.h"
#include "sym_load.h"

HANDLE hMutex;
int win_debug_level;

void *sysinfo_module = NULL;
sysinfo_networks_func sysinfo_network_ptr = NULL;
sysinfo_free_result_func sysinfo_free_result_ptr = NULL;

/** Prototypes **/
int Start_win32_Syscheck();

/* syscheck main thread */
void *skthread()
{

    Start_win32_Syscheck();

    return (NULL);
}

static void stop_wmodules()
{
    wmodule * cur_module;
    for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
        cur_module->context->destroy(cur_module->data);
    }
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

    if (sysinfo_module = so_get_module_handle("sysinfo"), sysinfo_module)
    {
        sysinfo_free_result_ptr = so_get_function_sym(sysinfo_module, "sysinfo_free_result");
        sysinfo_network_ptr = so_get_function_sym(sysinfo_module, "sysinfo_networks");
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

    /* state_main thread */
    w_agentd_state_init();
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
    w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_ACTIVE);

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

    atexit(stop_wmodules);

    /* Start logcollector -- main process here */
    LogCollectorStart();

    if (sysinfo_module){
        so_free_library(sysinfo_module);
    }

    WSACleanup();
    return (0);
}

/* SendMSG for Windows */
int SendMSG(__attribute__((unused)) int queue, const char *message, const char *locmsg, char loc)
{
    const char *pl;
    char tmpstr[OS_MAXSTR + 2];
    DWORD dwWaitResult;
    int retval = -1;
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
                    return retval;
                default:
                    merror("Error waiting mutex.");
                    return retval;
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
        w_agentd_state_update(INCREMENT_MSG_COUNT, NULL);
        if (send_msg(tmpstr, -1) >= 0) {
            retval = 0;
        }
    } else if (buffer_append(tmpstr) == 0) {
            retval = 0;
    }

    if (!ReleaseMutex(hMutex)) {
        merror("Error releasing mutex.");
    }
    return retval;
}

/* StartMQ for Windows */
int StartMQ(__attribute__((unused)) const char *path, __attribute__((unused)) short int type, __attribute__((unused)) short int n_tries)
{
    return (0);
}

char *get_agent_ip()
{
    char *agent_ip = NULL;

    cJSON *object;
    if (sysinfo_network_ptr && sysinfo_free_result_ptr) {
        sysinfo_network_ptr(&object);
        if (object) {
            const cJSON *iface = cJSON_GetObjectItem(object, "iface");
            if (iface) {
                const int size_ids = cJSON_GetArraySize(iface);
                for (int i = 0; i < size_ids; i++){
                    const cJSON *element = cJSON_GetArrayItem(iface, i);
                    if(!element) {
                        continue;
                    }
                    cJSON *gateway = cJSON_GetObjectItem(element, "gateway");
                    if(gateway && cJSON_GetStringValue(gateway) && 0 != strcmp(gateway->valuestring,"unkwown")) {
                        const cJSON *ipv4 = cJSON_GetObjectItem(element, "IPv4");
                        if (!ipv4) {
                            continue;
                        }
                        cJSON *address = cJSON_GetObjectItem(ipv4, "address");
                        if (address && cJSON_GetStringValue(address))
                        {
                            os_strdup(address->valuestring, agent_ip);
                            break;
                        }
                    }
                }
            }
            sysinfo_free_result_ptr(&object);
        }
    }
    return agent_ip;
}

#endif
