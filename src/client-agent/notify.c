/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "md5_op.h"
#include "os_net.h"
#include "agentd.h"
#include "metadata_provider.h"
#include "cJSON.h"

/* Keeps hash in memory until a change is identified */
static char *g_shared_mg_file_hash = NULL;
/* Keeps the timestamp of the last notification. */
static time_t g_saved_time = 0;

/* Return the names of the files in a directory */
char *getsharedfiles()
{
    unsigned int m_size = 64;
    char *ret;
    os_md5 md5sum;

    if (OS_MD5_File(SHAREDCFG_FILE, md5sum, OS_TEXT) != 0) {
        md5sum[0] = 'x';
        md5sum[1] = '\0';
    }

    /* Return just the MD5 hash (used in JSON keepalives) */
    ret = (char *)calloc(m_size + 1, sizeof(char));
    if (ret) {
        snprintf(ret, m_size, "%s", md5sum);
    }

    return (ret);
}


char *get_agent_ip()
{
    char agent_ip[IPSIZE + 1] = { '\0' };
    struct sockaddr_storage sas;
    socklen_t len = sizeof(sas);
    const int err = getsockname(agt->sock, (struct sockaddr *)&sas, &len);

    if (!err) {
        switch (sas.ss_family) {
            case AF_INET:
                get_ipv4_string(((struct sockaddr_in *)&sas)->sin_addr, agent_ip, IPSIZE);
                break;
            case AF_INET6:
                get_ipv6_string(((struct sockaddr_in6 *)&sas)->sin6_addr, agent_ip, IPSIZE);
                break;
            default:
                mdebug2("Unknown address family: %d", sas.ss_family);
                break;
        }
    } else {
        #ifdef WIN32
            mdebug2("getsockname() failed: %s", win_strerror(WSAGetLastError()));
        #else
            mdebug2("getsockname() failed: %s", strerror(errno));
        #endif
    }

    return strdup(agent_ip);
}

/* Clear merged hash cache, to be updated in the next iteration.*/
void clear_merged_hash_cache() {
    os_free(g_shared_mg_file_hash);
}

/* Build JSON keepalive message from metadata_provider and additional fields */
static char* build_json_keepalive(const char *agent_ip, const char *config_sum,
                                   const char *merged_sum, const char *labels) {
    agent_metadata_t metadata = {0};
    bool has_metadata = false;

    // Get metadata from shared memory (may not be available yet)
    if (metadata_provider_get(&metadata) == 0) {
        has_metadata = true;
    } else {
        mdebug2("Metadata not yet available, using minimal keepalive");
    }

    // Build JSON
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        if (has_metadata) {
            metadata_provider_free_metadata(&metadata);
        }
        return NULL;
    }

    cJSON_AddStringToObject(root, "version", "1.0");

    // Agent fields
    cJSON *agent = cJSON_CreateObject();
    if (has_metadata) {
        if (metadata.agent_id[0]) {
            cJSON_AddStringToObject(agent, "id", metadata.agent_id);
        }
        if (metadata.agent_name[0]) {
            cJSON_AddStringToObject(agent, "name", metadata.agent_name);
        }
        if (metadata.agent_version[0]) {
            cJSON_AddStringToObject(agent, "version", metadata.agent_version);
        }
    }
    if (config_sum && config_sum[0]) {
        cJSON_AddStringToObject(agent, "config_sum", config_sum);
    }
    if (merged_sum && merged_sum[0]) {
        cJSON_AddStringToObject(agent, "merged_sum", merged_sum);
    }
    if (agent_ip && agent_ip[0]) {
        cJSON_AddStringToObject(agent, "ip", agent_ip);
    }
    const char *uname_str = getuname();
    if (uname_str) {
        cJSON_AddStringToObject(agent, "uname", uname_str);
    }
    if (labels && labels[0]) {
        cJSON_AddStringToObject(agent, "labels", labels);
    }

    // Add groups array if available
    if (has_metadata && metadata.groups_count > 0 && metadata.groups) {
        cJSON *groups_array = cJSON_CreateArray();
        for (size_t i = 0; i < metadata.groups_count; i++) {
            if (metadata.groups[i] && metadata.groups[i][0]) {
                cJSON_AddItemToArray(groups_array, cJSON_CreateString(metadata.groups[i]));
            }
        }
        cJSON_AddItemToObject(agent, "groups", groups_array);
    }

    cJSON_AddItemToObject(root, "agent", agent);

    // Host fields (only if metadata available)
    if (has_metadata) {
        cJSON *host = cJSON_CreateObject();
        if (metadata.hostname[0]) {
            cJSON_AddStringToObject(host, "hostname", metadata.hostname);
        }
        if (metadata.architecture[0]) {
            cJSON_AddStringToObject(host, "architecture", metadata.architecture);
        }

        // Host OS fields
        cJSON *os = cJSON_CreateObject();
        if (metadata.os_name[0]) {
            cJSON_AddStringToObject(os, "name", metadata.os_name);
        }
        if (metadata.os_version[0]) {
            cJSON_AddStringToObject(os, "version", metadata.os_version);
        }
        if (metadata.os_platform[0]) {
            cJSON_AddStringToObject(os, "platform", metadata.os_platform);
        }
        if (metadata.os_type[0]) {
            cJSON_AddStringToObject(os, "type", metadata.os_type);
        }
        cJSON_AddItemToObject(host, "os", os);
        cJSON_AddItemToObject(root, "host", host);
    }

    // Cluster fields (only if metadata available and cluster info present)
    if (has_metadata) {
        cJSON *cluster = cJSON_CreateObject();
        bool has_cluster_info = false;

        if (metadata.cluster_name[0]) {
            cJSON_AddStringToObject(cluster, "name", metadata.cluster_name);
            has_cluster_info = true;
        }
        if (metadata.cluster_node[0]) {
            cJSON_AddStringToObject(cluster, "node", metadata.cluster_node);
            has_cluster_info = true;
        }

        if (has_cluster_info) {
            cJSON_AddItemToObject(root, "cluster", cluster);
        } else {
            cJSON_Delete(cluster);
        }
    }

    // Convert to string
    char *json_str = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    if (has_metadata) {
        metadata_provider_free_metadata(&metadata);
    }

    return json_str;
}

/* Periodically send notification to server */
void run_notify()
{
    char tmp_msg[OS_MAXSTR - OS_HEADER_SIZE + 2];
    static char tmp_labels[OS_MAXSTR - OS_SIZE_2048] = { '\0' };
    static wlabel_t *last_labels_ptr = NULL;
    os_md5 md5sum = {0};
    time_t curr_time;
    static char agent_ip[IPSIZE + 1] = { '\0' };
    static time_t last_update = 0;

    tmp_msg[OS_MAXSTR - OS_HEADER_SIZE + 1] = '\0';
    curr_time = time(0);

#ifndef ONEWAY_ENABLED
    /* Check if the server has responded */
    if ((curr_time - available_server) > agt->max_time_reconnect_try) {
        /* If response is not available, set lock and wait for it */
        mwarn(SERVER_UNAV);
        os_setwait();
        w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_NACTIVE);

        /* Send sync message */
        start_agent(0);

        minfo(SERVER_UP);
        os_delwait();
        w_agentd_state_update(UPDATE_STATUS, (void *) GA_STATUS_ACTIVE);
    }
#endif

    /* Check if time has elapsed */
    if ((curr_time - g_saved_time) < agt->notify_time) {
        return;
    }
    g_saved_time = curr_time;

    mdebug1("Sending agent notification.");

    /* Send the message
     * Message is going to be the uname\n checksum file\n checksum file\n
     */

    /* Get uname */
    if (!getuname()) {
        merror(MEM_ERROR, errno, strerror(errno));
    }

    /* Format labeled data
     * Limit maximum size of the labels to avoid truncation of the keep-alive message
     */
    if (agt->labels != last_labels_ptr) {
        tmp_labels[0] = '\0';
        if (labels_format(agt->labels, tmp_labels, OS_MAXSTR - OS_SIZE_2048) < 0) {
            mwarn("Too large labeled data. Not all labels will be shown in the keep-alive messages.");
        }
        last_labels_ptr = agt->labels;
    }

    /* Get shared files */
    struct stat stat_fd;
    if (!g_shared_mg_file_hash) {
        g_shared_mg_file_hash = getsharedfiles();
        if (!g_shared_mg_file_hash) {
            merror(MEM_ERROR, errno, strerror(errno));
            return;
        }
    } else if(w_stat(SHAREDCFG_FILE, &stat_fd) == -1 && ENOENT == errno) {
        clear_merged_hash_cache();
    }

    time_t now = time(NULL);
    if ((now - last_update) >= agt->main_ip_update_interval) {
        // Update agent_ip considering main_ip_update_interval value
        last_update = now;
        char *tmp_agent_ip = get_agent_ip();

        if (tmp_agent_ip) {
            strncpy(agent_ip, tmp_agent_ip, IPSIZE);
            os_free(tmp_agent_ip);
        } else {
           mdebug1("Cannot update host IP.");
           *agent_ip = '\0';
        }
    }

    /* Compute client.keys MD5 sum if available */
    if ((File_DateofChange(AGENTCONFIG) > 0) && (OS_MD5_File(AGENTCONFIG, md5sum, OS_TEXT) != 0)) {
        md5sum[0] = '\0';  // Clear if failed
    }

    /* Create JSON keepalive message */
    char *json_keepalive = build_json_keepalive(
        agent_ip[0] ? agent_ip : NULL,
        md5sum[0] ? md5sum : NULL,
        g_shared_mg_file_hash,
        tmp_labels[0] ? tmp_labels : NULL
    );
    if (!json_keepalive) {
        merror("Failed to build JSON keepalive");
        return;
    }

    snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "%s%s", CONTROL_HEADER, json_keepalive);
    os_free(json_keepalive);

    /* Send status message */
    mdebug2("Sending keep alive: %s", tmp_msg);
    send_msg(tmp_msg, -1);

    w_agentd_state_update(UPDATE_KEEPALIVE, (void *) &curr_time);
    return;
}
