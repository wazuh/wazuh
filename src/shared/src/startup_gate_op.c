/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net.h"
#include "startup_gate_op.h"
#if defined(CLIENT) && defined(WIN32)
#include "agentd.h"
#endif

#define STARTUP_GATE_COMMAND "getstartupgate"
#define STARTUP_GATE_POLL_INTERVAL 1
#define STARTUP_GATE_LOG_INTERVAL 30

#if defined(CLIENT) && !defined(WIN32)
static bool startup_gate_parse_status(const char *response, bool *ready, char *reason, size_t reason_size) {
    bool parsed = false;
    cJSON *root = NULL;
    cJSON *ready_field = NULL;
    cJSON *reason_field = NULL;

    if (!response || !ready || strncmp(response, "ok ", 3) != 0) {
        return false;
    }

    root = cJSON_Parse(response + 3);
    if (!root) {
        return false;
    }

    ready_field = cJSON_GetObjectItem(root, "ready");
    if (ready_field && cJSON_IsBool(ready_field)) {
        *ready = cJSON_IsTrue(ready_field);
        parsed = true;
    }

    if (parsed && reason && reason_size > 0) {
        reason_field = cJSON_GetObjectItem(root, "reason");
        if (reason_field && cJSON_IsString(reason_field) && reason_field->valuestring) {
            snprintf(reason, reason_size, "%s", reason_field->valuestring);
        } else {
            snprintf(reason, reason_size, "unknown");
        }
    }

    cJSON_Delete(root);
    return parsed;
}
#endif

#if defined(CLIENT)
static bool startup_gate_query_status(bool *ready, char *reason, size_t reason_size) {
#if !defined(WIN32)
    bool parsed = false;
    int sock = -1;
    char response[OS_MAXSTR + 1] = {0};
    ssize_t recv_len = 0;
#else
    bool ready_value = false;
    char reason_value[OS_SIZE_128] = {0};
#endif

    if (!ready) {
        return false;
    }

#if defined(WIN32)
    startup_gate_get_status(&ready_value, reason_value, sizeof(reason_value));
    *ready = ready_value;

    if (reason && reason_size > 0) {
        snprintf(reason, reason_size, "%s", reason_value[0] ? reason_value : "unknown");
    }

    return true;
#else
    sock = OS_ConnectUnixDomain(AG_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR);
    if (sock < 0) {
        return false;
    }

    if (OS_SendSecureTCP(sock, strlen(STARTUP_GATE_COMMAND), STARTUP_GATE_COMMAND) != 0) {
        close(sock);
        return false;
    }

    recv_len = OS_RecvSecureTCP(sock, response, OS_MAXSTR);
    close(sock);

    if (recv_len <= 0 || recv_len > OS_MAXSTR) {
        return false;
    }

    response[recv_len] = '\0';
    parsed = startup_gate_parse_status(response, ready, reason, reason_size);

    return parsed;
#endif
}
#endif

void startup_gate_wait_for_ready(const char *module_name) {
#if defined(CLIENT)
    bool waiting_logged = false;
    unsigned int waiting_loops = 0;
    char last_reason[OS_SIZE_128] = {0};
    const char *name = module_name && module_name[0] ? module_name : "module";

    while (FOREVER()) {
        bool ready = false;
        bool got_status = false;
        bool should_log = false;
        char reason[OS_SIZE_128] = {0};

        got_status = startup_gate_query_status(&ready, reason, sizeof(reason));
        if (got_status && ready) {
            if (waiting_logged) {
                minfo("Startup hash gate released for '%s' (%s).", name, reason[0] ? reason : "unknown");
            }
            return;
        }

        should_log = !waiting_logged || (waiting_loops % STARTUP_GATE_LOG_INTERVAL == 0);
        if (got_status && strncmp(last_reason, reason, sizeof(last_reason)) != 0) {
            should_log = true;
        }

        if (should_log) {
            if (got_status) {
                minfo("Startup hash gate is blocking '%s' (%s).", name, reason[0] ? reason : "unknown");
                snprintf(last_reason, sizeof(last_reason), "%s", reason);
            } else {
                minfo("Startup hash gate is blocking '%s' (waiting for agentd startup gate status).", name);
                last_reason[0] = '\0';
            }
        }

        waiting_logged = true;
        waiting_loops++;
        sleep(STARTUP_GATE_POLL_INTERVAL);
    }
#else
    (void)module_name;
#endif
}
