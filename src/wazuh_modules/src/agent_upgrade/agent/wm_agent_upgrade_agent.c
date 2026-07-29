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

const char* upgrade_values[] = {
    [WM_UPGRADE_SUCCESSFUL] = "0", [WM_UPGRADE_FAILED_INTERMEDIATE] = "1", [WM_UPGRADE_FAILED] = "2"};

const char* upgrade_messages[] = {[WM_UPGRADE_SUCCESSFUL] = "Upgrade was successful",
                                  [WM_UPGRADE_FAILED_INTERMEDIATE] = "Upgrade failed: intermediate version required",
                                  [WM_UPGRADE_FAILED] = "Upgrade failed"};

// CA certificates
char** wcom_ca_store = NULL;

#ifndef WIN32

/**
 * Listen to the upgrade socket in order to receive commands
 * @return only on errors, socket will be closed
 * */
STATIC void* wm_agent_upgrade_listen_messages(__attribute__((unused)) void* arg);

#endif

/**
 * Checks if an agent has been recently upgraded, by reading the upgrade_result file.
 * If a result is present, it is logged locally (purely informational: since #37733/#37834
 * the agent never reports the outcome back to the manager) and the result file is removed
 * so a stale result cannot be picked up again on the next start. Either way, upgrades are
 * unconditionally re-allowed afterward -- there is no manager round-trip left to wait for.
 * @param agent_config Agent configuration parameters (unused; kept for call-site stability)
 * */
STATIC void wm_agent_upgrade_check_status(const wm_agent_configs* agent_config) __attribute__((nonnull));

/**
 * Checks the upgrade_result file for a numeric code that determines the result
 * of the upgrade operation.
 * @param raw_code output parameter: the raw numeric code read from the upgrade_result file
 * @return a flag indicating if a valid result was found
 * @retval true a valid numeric code was found on the upgrade_result file (written to raw_code)
 * @retval false either the upgrade_result file does not exist or contains invalid information
 * */
STATIC bool wm_upgrade_agent_search_upgrade_result(unsigned int* raw_code);

void wm_agent_upgrade_start_agent_module(const wm_agent_configs* agent_config, const int enabled)
{

    // Check if module is enabled
    if (!enabled)
    {
        allow_upgrades = false;
    }
    else
    {
        mtinfo(WM_AGENT_UPGRADE_LOGTAG, STARTUP_MSG, (int)getpid());
    }

#ifndef WIN32
    w_create_thread(wm_agent_upgrade_listen_messages, NULL);
#endif

    if (enabled)
    {
        wm_agent_upgrade_check_status(agent_config);
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

STATIC void wm_agent_upgrade_check_status(const wm_agent_configs* agent_config)
{
    // No longer used: the redesigned, synchronous check_status() has no manager round-trip
    // to size a retry/backoff loop for (see the function's own header comment, #37733/#37834).
    (void)agent_config;

    // Wait until the pkg_installer script verifies the agent was connected and writes the
    // upgrade_result file.
    wm_sleep_interruptible(WM_AGENT_UPGRADE_RESULT_WAIT_TIME);
    if (wm_shutdown_requested)
    {
        return;
    }

    unsigned int raw_code = 0;
    if (wm_upgrade_agent_search_upgrade_result(&raw_code))
    {
        wm_upgrade_agent_state state =
            (raw_code < WM_UPGRADE_MAX_STATE) ? (wm_upgrade_agent_state)raw_code : WM_UPGRADE_FAILED;

        // Purely informational (#37733/#37834): nothing is sent to the manager anymore.
        mtinfo(WM_AGENT_UPGRADE_LOGTAG, "%s", upgrade_messages[state]);

        if (remove(WM_AGENT_UPGRADE_RESULT_FILE) != 0)
        {
            mtdebug1(WM_AGENT_UPGRADE_LOGTAG, WM_UPGRADE_ERASE_FILE_ERROR, "check_status", WM_AGENT_UPGRADE_RESULT_FILE);
        }
    }

    // No manager round-trip is left to gate this on: always re-allow upgrades once the
    // leftover result (if any) has been handled locally.
    allow_upgrades = true;
}

STATIC bool wm_upgrade_agent_search_upgrade_result(unsigned int* raw_code)
{
    char buffer[20];
    const char* PATH = WM_AGENT_UPGRADE_RESULT_FILE;

    FILE* result_file = wfopen(PATH, "r");
    if (result_file)
    {
        if (fgets(buffer, 20, result_file) == NULL)
        {
            fclose(result_file);
            return false;
        }
        fclose(result_file);

        char* endptr;
        unsigned long parsed_code = strtoul(buffer, &endptr, 10);
        if (endptr != buffer && (*endptr == '\0' || *endptr == '\n' || *endptr == '\r'))
        {
            *raw_code = (unsigned int)parsed_code;
            return true;
        }
    }
    return false;
}
