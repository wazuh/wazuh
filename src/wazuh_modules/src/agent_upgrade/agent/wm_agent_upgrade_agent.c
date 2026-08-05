/*
 * Wazuh Module for Agent Upgrading
 * Copyright (C) 2015, Wazuh Inc.
 * July 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "wm_agent_upgrade_agent.h"
#ifndef WIN32
#include "os_net.h"
#endif

#ifdef WAZUH_UNIT_TESTING
#ifdef WIN32
#include "../unit_tests/wrappers/windows/libc/stdio_wrappers.h"
#include "../unit_tests/wrappers/windows/synchapi_wrappers.h"
#endif
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

static const char* upgrade_messages[] = {[WM_UPGRADE_SUCCESSFUL] = "Upgrade was successful",
                                         [WM_UPGRADE_FAILED_INTERMEDIATE] = "Upgrade failed: intermediate version required",
                                         [WM_UPGRADE_FAILED] = "Upgrade failed"};

static const char* upgrade_statuses[] = {[WM_UPGRADE_SUCCESSFUL] = "Done",
                                         [WM_UPGRADE_FAILED_INTERMEDIATE] = "Failed",
                                         [WM_UPGRADE_FAILED] = "Failed"};

// CA certificates
char** wcom_ca_store = NULL;

/* Predicate for StartMQPredicated: aborts the open-queue retry loop on shutdown so the
 * result reporter cannot block past the cooperative cancellation deadline. */
STATIC bool wm_agent_upgrade_is_shutting_down(void)
{
    return wm_shutdown_requested != 0;
}

#ifndef WIN32

/**
 * Listen to the upgrade socket in order to receive commands
 * @return only on errors, socket will be closed
 * */
STATIC void* wm_agent_upgrade_listen_messages(__attribute__((unused)) void* arg);

#endif

/**
 * Checks if an agent has been recently upgraded, by reading the upgrade_result file, and
 * reports the outcome as a stateless event. Blocks until the agent's event queue is up.
 * */
STATIC void wm_agent_upgrade_check_status(void);

/**
 * Checks in the upgrade_results file for a code that determines the result of the upgrade
 * operation and reports it as a stateless event, erasing the file afterwards (#38103).
 * @param queue_fd file descriptor of the queue where the event will be sent
 * @return a flag indicating whether the file should be read again
 * @retval true the installer has not written a complete code yet, so retry
 * @retval false the result was reported and erased, or the file holds no usable code
 * */
STATIC bool wm_upgrade_agent_search_upgrade_result(int* queue_fd);

/**
 * Reads the upgrade_result file if it is present and reports the result as a stateless
 * event (#38103), the same egress every other module event takes: the frame goes to
 * DEFAULTQUEUE, EventForward() hands it to the HTTPS /stateless accumulator.
 *
 * Example event:
 * {
 *	  "collector": "upgrade_result",
 *	  "module": "agent-upgrade",
 *	  "data": {
 *        "status": "Failed",
 *        "error": 2,
 *        "message": "Upgrade failed"
 *	  }
 * }
 * @param queue_fd File descriptor of the event queue
 * @param state upgrade result state
 * @param raw_code raw numeric code read from upgrade_result file
 * */
STATIC void wm_upgrade_agent_send_result_event(int* queue_fd, wm_upgrade_agent_state state, unsigned int raw_code);

void wm_agent_upgrade_start_agent_module(__attribute__((unused)) const wm_agent_configs* agent_config, const int enabled)
{

    // Check if module is enabled
    if (!enabled)
    {
        allow_upgrades = false;
    }
    else
    {
        mtinfo(WM_AGENT_UPGRADE_LOGTAG, STARTUP_MSG, (int)getpid());
        allow_upgrades = true;
    }

#ifndef WIN32
    w_create_thread(wm_agent_upgrade_listen_messages, NULL);
#endif

    if (enabled)
    {
        // Runs on the module's own thread, so blocking here waits out the upgrade only
        wm_agent_upgrade_check_status();
    }
}

#ifndef WIN32

STATIC void* wm_agent_upgrade_listen_messages(__attribute__((unused)) void* arg)
{
    // Initialize socket
    char sockname[PATH_MAX + 1];

    strcpy(sockname, AGENT_UPGRADE_SOCK);

    int sock = OS_BindUnixDomainWithPerms(sockname, SOCK_STREAM, OS_MAXSTR, getuid(), wm_getGroupID(), 0660);
    if (sock < 0)
    {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_BIND_SOCK_ERROR, AGENT_UPGRADE_SOCK, strerror(errno));
        return NULL;
    }

    while (!wm_shutdown_requested)
    {
        // listen - wait connection
        fd_set fdset;
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (wm_select_interruptible(sock, &fdset))
        {
            case -1:
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SELECT_ERROR, strerror(errno));
                close(sock);
                return NULL;
            case 0: continue;
        }

        // Accept
        int peer;
        if (peer = accept(sock, NULL, NULL), peer < 0)
        {
            if (errno != EINTR)
            {
                mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ACCEPT_ERROR, strerror(errno));
            }
            continue;
        }

        // Get request string
        char* buffer = NULL;

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        int length;
        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length)
        {
            case OS_SOCKTERR: mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_SOCKTERR_ERROR); break;
            case -1: mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RECV_ERROR, strerror(errno)); break;
            case 0: mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_EMPTY_MESSAGE); break;
            default:
                mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_INCOMMING_MESSAGE, buffer);
                char* message = NULL;
                size_t length = wm_agent_upgrade_process_command(buffer, &message);

                mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_RESPONSE_MESSAGE, message);
                OS_SendSecureTCP(peer, length, message);
                os_free(message);
                break;
        }

        os_free(buffer);
        close(peer);

#ifdef WAZUH_UNIT_TESTING
        break;
#endif
    }

    close(sock);

    return NULL;
}

#endif

STATIC void wm_agent_upgrade_check_status(void)
{
    /**
     * Nothing to report unless an upgrade just ran. The installer creates its in-progress
     * lock before it restarts this agent and removes it only after writing
     * upgrade_result, so anywhere between those two points at least one of the two files
     * is on disk. Neither present is an ordinary restart
     */
    if (!w_is_file(WM_AGENT_UPGRADE_RESULT_FILE) && !w_is_file(WM_AGENT_UPGRADE_LOCK_FILE))
    {
        return;
    }

    /**
     *  StartMQ will wait until agent connection which is when the pkg_install.sh will write
     *  the upgrade result. The predicate aborts the retry loop on shutdown so the module
     *  does not block past the cooperative cancellation deadline.
     */
    int queue_fd = StartMQPredicated(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS, wm_agent_upgrade_is_shutting_down);

    if (wm_shutdown_requested)
    {
        return;
    }

    if (queue_fd < 0)
    {
        mterror(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_QUEUE_FD);
        return;
    }

    /**
     * The result is reported as a stateless event and the file is erased in the same pass
     */
    for (int reads = 0; reads < WM_AGENT_UPGRADE_RESULT_MAX_READS; reads++)
    {
        wm_sleep_interruptible(reads == 0 ? WM_AGENT_UPGRADE_RESULT_WAIT_TIME : WM_AGENT_UPGRADE_RESULT_RETRY_TIME);
        if (wm_shutdown_requested)
        {
            break;
        }

        if (!wm_upgrade_agent_search_upgrade_result(&queue_fd))
        {
            break;
        }
    }

#ifndef WIN32
    close(queue_fd);
#endif
}

STATIC bool wm_upgrade_agent_search_upgrade_result(int* queue_fd)
{
    char buffer[20];
    const char* PATH = WM_AGENT_UPGRADE_RESULT_FILE;

    FILE* result_file = wfopen(PATH, "r");
    if (!result_file)
    {
        /* The installer writes this only after the upgraded agent reconnects, so an
         * absent file means "not written yet", not "no upgrade to report". */
        return true;
    }

    if (fgets(buffer, 20, result_file) == NULL)
    {
        fclose(result_file);
        return true;
    }
    fclose(result_file);

    char* endptr;
    unsigned long raw_code = strtoul(buffer, &endptr, 10);
    if (endptr == buffer || (*endptr != '\0' && *endptr != '\n' && *endptr != '\r'))
    {
        // Not a partial write but content no code can be made of: nothing to wait for
        return false;
    }

    wm_upgrade_agent_state state =
        (raw_code < WM_UPGRADE_MAX_STATE) ? (wm_upgrade_agent_state)raw_code : WM_UPGRADE_FAILED;
    wm_upgrade_agent_send_result_event(queue_fd, state, (unsigned int)raw_code);

    /* The manager used to clear this file by answering the ack with
     * clear_upgrade_result (#38103). A stateless event is not answered, so the
     * result is reported once and dropped here instead of retried forever. */
    if (remove(WM_AGENT_UPGRADE_RESULT_FILE) != 0)
    {
        mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ERASE_FILE_ERROR, "check_status", WM_AGENT_UPGRADE_RESULT_FILE);
    }

    return false;
}

STATIC void wm_upgrade_agent_send_result_event(int* queue_fd, wm_upgrade_agent_state state, unsigned int raw_code)
{
    int msg_delay = 1000000 / wm_max_eps;
    cJSON* root = cJSON_CreateObject();
    cJSON* data = cJSON_CreateObject();

    cJSON_AddStringToObject(root, "collector", "upgrade_result");
    cJSON_AddStringToObject(root, "module", AGENT_UPGRADE_WM_NAME);
    cJSON_AddNumberToObject(data, "error", raw_code);
    cJSON_AddStringToObject(data, "message", upgrade_messages[state]);
    cJSON_AddStringToObject(data, "status", upgrade_statuses[state]);
    cJSON_AddItemToObject(root, "data", data);

    char* msg_string = cJSON_PrintUnformatted(root);
    /* LOCALFILE_MQ with the module name as location: the frame every other module
     * event uses, so EventForward() routes it to /stateless instead of the legacy
     * "u:upgrade_module:" header remoted special-cases (secure.c:1141). */
    if (wm_sendmsg(msg_delay, *queue_fd, msg_string, AGENT_UPGRADE_WM_NAME, LOCALFILE_MQ) < 0)
    {
        mterror(WM_AGENT_UPGRADE_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
        if (*queue_fd >= 0)
        {
            close(*queue_fd);
        }
        *queue_fd = StartMQPredicated(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS, wm_agent_upgrade_is_shutting_down);
        if (wm_shutdown_requested)
        {
            os_free(msg_string);
            cJSON_Delete(root);
            return;
        }
        if (*queue_fd < 0)
        {
            mterror_exit(WM_AGENT_UPGRADE_LOGTAG, QUEUE_FATAL, DEFAULTQUEUE);
        }
    }

    mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ACK_MESSAGE, msg_string);
    os_free(msg_string);
    cJSON_Delete(root);
}
