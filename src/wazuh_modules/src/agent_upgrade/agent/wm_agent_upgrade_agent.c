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

// CA certificates
char** wcom_ca_store = NULL;

#ifndef WIN32

/**
 * Listen to the upgrade socket in order to receive commands
 * @return only on errors, socket will be closed
 * */
STATIC void* wm_agent_upgrade_listen_messages(__attribute__((unused)) void* arg);

#endif

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
