/* Remote request listener
 * Copyright (C) 2015, Wazuh Inc.
 * Mar 12, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <shared.h>
#include "agentd.h"
#include "module_report.h"
#include "os_net.h"
#include "wmodules.h"

/* Name this daemon reports itself under in the /config and /stats documents. */
#define AGCOM_MODULE_NAME "agent"


size_t agcom_dispatch(char * command, char ** output){

    char *rcv_comm = command;
    char *rcv_args = NULL;

    if ((rcv_args = strchr(rcv_comm, ' '))){
        *rcv_args = '\0';
        rcv_args++;
    }

    if (strcmp(rcv_comm, "getconfig") == 0){
        // getconfig section
        if (!rcv_args){
            mdebug1("AGCOM getconfig needs arguments.");
            os_strdup("err AGCOM getconfig needs arguments", *output);
            return strlen(*output);
        }
        return agcom_getconfig(rcv_args, output);

    } else if (strcmp(rcv_comm, "getallconfig") == 0) {
        return agcom_getallconfig(output);

    } else if (strcmp(rcv_comm, "getallstats") == 0) {
        return agcom_getallstats(output);

    } else if (strcmp(rcv_comm, "getstate") == 0) {
        return agcom_getstate(output);
    } else if (strcmp(rcv_comm, "gethandshake") == 0) {
        return agcom_gethandshake(output);
    } else if (strcmp(rcv_comm, "getstartupgate") == 0) {
        return agcom_getstartupgate(output);
    } else if (strcmp(rcv_comm, "getdoclimits") == 0) {
        if (!rcv_args) {
            mdebug1("AGCOM getdoclimits needs arguments (module name).");
            os_strdup("err AGCOM getdoclimits needs arguments", *output);
            return strlen(*output);
        }

        cJSON *cfg = getDocumentLimits(rcv_args);
        if (cfg) {
            os_strdup("ok", *output);
            char *json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            os_free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            mdebug1("AGCOM Module limits not configured for module '%s'.", rcv_args);
            os_strdup("err Module limits not configured", *output);
            return strlen(*output);
        }
    } else {
        mdebug1("AGCOM Unrecognized command '%s'.", rcv_comm);
        os_strdup("err Unrecognized command", *output);
        return strlen(*output);
    }
}

size_t agcom_getconfig(const char * section, char ** output) {

    cJSON *cfg;
    char *json_str;

    /* "client" is the 4.x name of this section and stays accepted so the Server
     * API's existing /config/agent/client path keeps working; the document it
     * returns is keyed "agent" either way. */
    if (strcmp(section, "agent") == 0 || strcmp(section, "client") == 0){
        if (cfg = getAgentConfig(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
    } else if (strcmp(section, "internal") == 0){
        if (cfg = getAgentInternalOptions(), cfg) {
            *output = strdup("ok");
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
#ifndef WIN32
    } else if (strcmp(section, "anti_tampering") == 0){
        if (cfg = getAntiTamperingConfig(), cfg) {
            os_strdup("ok", *output);
            json_str = cJSON_PrintUnformatted(cfg);
            wm_strcat(output, json_str, ' ');
            os_free(json_str);
            cJSON_Delete(cfg);
            return strlen(*output);
        } else {
            goto error;
        }
#endif
    } else {
        goto error;
    }
error:
    mdebug1("At AGCOM getconfig: Could not get '%s' section", section);
    os_strdup("err Could not get requested section", *output);
    return strlen(*output);
}

size_t agcom_getallconfig(char ** output) {

    cJSON *report = cJSON_CreateObject();
    cJSON *body = cJSON_CreateObject();

    module_report_merge(body, getAgentConfig());
    module_report_merge(body, getAgentInternalOptions());
#ifndef WIN32
    module_report_merge(body, getAntiTamperingConfig());
#endif

    module_report_add(report, AGCOM_MODULE_NAME, body);
    return module_report_reply(report, output);
}

/* "getstate" is a socket call, and the {"error","data"} envelope is its framing:
 * the body itself carries no error channel. Added here rather than inside
 * w_agentd_state_get() so the /stats push, where the response status is the
 * error channel, can send the body bare. */
size_t agcom_getstate(char ** output) {

    cJSON *envelope = cJSON_CreateObject();
    cJSON *body = w_agentd_state_get();
    char *json_str = NULL;

    if (!envelope || !body) {
        cJSON_Delete(envelope);
        cJSON_Delete(body);
        os_strdup("err Could not build the agent state", *output);
        return strlen(*output);
    }

    cJSON_AddNumberToObject(envelope, W_AGENTD_JSON_ERROR, 0);
    cJSON_AddItemToObject(envelope, W_AGENTD_JSON_DATA, body);

    json_str = cJSON_PrintUnformatted(envelope);
    cJSON_Delete(envelope);

    if (!json_str) {
        os_strdup("err Could not serialize the agent state", *output);
        return strlen(*output);
    }

    *output = json_str;
    return strlen(*output);
}

size_t agcom_getallstats(char ** output) {

    cJSON *report = cJSON_CreateObject();

    module_report_add(report, AGCOM_MODULE_NAME, w_agentd_state_get());
    return module_report_reply(report, output);
}

/**
 * @brief Return cluster and group info received from the last handshake as JSON.
 * @param output Pointer to store the allocated response string.
 * @return Length of the response string.
 */
size_t agcom_gethandshake(char **output) {
    /* Snapshot the handshake globals under lock: they may be rewritten concurrently by
     * the connection thread on every reconnect, and agent-info now polls this every cycle
     * (not just once at startup), so a torn read is no longer a one-time-only risk. */
    char cluster_name_snapshot[256];
    char agent_groups_snapshot[OS_SIZE_65536];

    w_mutex_lock(&agent_handshake_mutex);
    strncpy(cluster_name_snapshot, agent_cluster_name, sizeof(cluster_name_snapshot) - 1);
    cluster_name_snapshot[sizeof(cluster_name_snapshot) - 1] = '\0';
    strncpy(agent_groups_snapshot, agent_agent_groups, sizeof(agent_groups_snapshot) - 1);
    agent_groups_snapshot[sizeof(agent_groups_snapshot) - 1] = '\0';
    w_mutex_unlock(&agent_handshake_mutex);

    if (cluster_name_snapshot[0] == '\0') {
        mdebug1("Cluster name not received yet from manager.");
        os_strdup("err Cluster name not received yet from manager", *output);
        return strlen(*output);
    }

    /* Empty agent_groups is allowed - fallback to merge.mg will be used */

    char *json_str = NULL;
    cJSON *root = cJSON_CreateObject();

    if (root) {
        cJSON_AddStringToObject(root, "cluster_name", cluster_name_snapshot);
        cJSON_AddStringToObject(root, "agent_groups", agent_groups_snapshot);
        json_str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
    }

    if (json_str) {
        os_strdup(json_str, *output);
        os_free(json_str);
    } else {
        mdebug1("Failed to create handshake JSON response.");
        os_strdup("err Failed to create handshake JSON response", *output);
        return strlen(*output);
    }

    mdebug1("Returning handshake JSON response: %s", *output);
    return strlen(*output);
}

/**
 * @brief Return the startup gate status as a JSON response.
 * @param output Pointer to store the allocated response string.
 * @return Length of the response string.
 */
size_t agcom_getstartupgate(char **output) {
    bool ready = false;
    char reason[OS_SIZE_128] = {0};
    cJSON *root = NULL;
    char *json_str = NULL;

    startup_gate_get_status(&ready, reason, sizeof(reason));

    root = cJSON_CreateObject();
    if (!root) {
        os_strdup("err Failed to create startup gate response", *output);
        return strlen(*output);
    }

    cJSON_AddBoolToObject(root, "ready", ready);
    cJSON_AddStringToObject(root, "reason", reason[0] ? reason : "unknown");

    json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);

    if (!json_str) {
        os_strdup("err Failed to serialize startup gate response", *output);
        return strlen(*output);
    }

    os_strdup("ok", *output);
    wm_strcat(output, json_str, ' ');
    os_free(json_str);

    return strlen(*output);
}

/**
 * @brief Return document limits for a given module as a JSON object.
 * @param module Module name ("fim", "syscollector", or "sca").
 * @return cJSON object with the limits, or NULL if module is unknown or limits not received.
 */
cJSON *getDocumentLimits(const char *module) {
    if (!module) {
        return NULL;
    }

    if (!agent_module_limits.limits_received) {
        return NULL;
    }

    cJSON *cfg = cJSON_CreateObject();
    if (!cfg) {
        return NULL;
    }

    if (strcmp(module, "fim") == 0) {
        cJSON_AddNumberToObject(cfg, "file", agent_module_limits.fim.file);
        cJSON_AddNumberToObject(cfg, "registry_key", agent_module_limits.fim.registry_key);
        cJSON_AddNumberToObject(cfg, "registry_value", agent_module_limits.fim.registry_value);
    } else if (strcmp(module, "syscollector") == 0) {
        cJSON_AddNumberToObject(cfg, "hotfixes", agent_module_limits.syscollector.hotfixes);
        cJSON_AddNumberToObject(cfg, "packages", agent_module_limits.syscollector.packages);
        cJSON_AddNumberToObject(cfg, "processes", agent_module_limits.syscollector.processes);
        cJSON_AddNumberToObject(cfg, "ports", agent_module_limits.syscollector.ports);
        cJSON_AddNumberToObject(cfg, "network_iface", agent_module_limits.syscollector.network_iface);
        cJSON_AddNumberToObject(cfg, "network_protocol", agent_module_limits.syscollector.network_protocol);
        cJSON_AddNumberToObject(cfg, "network_address", agent_module_limits.syscollector.network_address);
        cJSON_AddNumberToObject(cfg, "hardware", agent_module_limits.syscollector.hardware);
        cJSON_AddNumberToObject(cfg, "os_info", agent_module_limits.syscollector.os_info);
        cJSON_AddNumberToObject(cfg, "users", agent_module_limits.syscollector.users);
        cJSON_AddNumberToObject(cfg, "groups", agent_module_limits.syscollector.groups);
        cJSON_AddNumberToObject(cfg, "services", agent_module_limits.syscollector.services);
        cJSON_AddNumberToObject(cfg, "browser_extensions", agent_module_limits.syscollector.browser_extensions);
    } else if (strcmp(module, "sca") == 0) {
        cJSON_AddNumberToObject(cfg, "checks", agent_module_limits.sca.checks);
    } else {
        cJSON_Delete(cfg);
        return NULL;
    }

    return cfg;
}

#ifndef WIN32
void * agcom_main(__attribute__((unused)) void * arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response = NULL;
    ssize_t length;
    fd_set fdset;

    mdebug1("Local requests thread ready");

    // Bind socket
    if (sock = OS_BindUnixDomain(AG_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': (%d) %s.",
               AG_LOCAL_SOCK, errno, strerror(errno));
        return NULL;
    }

    // Main loop
    while (1) {
        // Select
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("At agcom_main(): select(): %s", strerror(errno));
            }
            continue;
        case 0:
            continue;
        }

        // Accept
        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                merror("At agcom_main(): accept(): %s", strerror(errno));
            }
            continue;
        }

        // Receive
        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer, OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror("At agcom_main(): OS_RecvSecureTCP(): response size is bigger than expected");
            break;
        case -1:
            merror("At agcom_main(): OS_RecvSecureTCP(): %s", strerror(errno));
            break;
        case 0:
            mdebug1("Empty message from local client.");
            close(peer);
            os_free(buffer);
            continue;
        case OS_MAXLEN:
            merror("Received message > %i", MAX_DYN_STR);
            close(peer);
            os_free(buffer);
            continue;
        default:
            // Dispatch
            length = agcom_dispatch(buffer, &response);
            // Send
            OS_SendSecureTCP(peer, length, response);
            os_free(response);
            close(peer);
        }
        os_free(buffer);
    }

    /* Intentional cleanup code: the while(1) loop above currently exits only via
     * merror_exit(). This block ensures proper resource release if a graceful
     * exit path is added in the future. */
    // coverity[unreachable]
    close(sock);
    return NULL;
}
#endif /* !WIN32 */
