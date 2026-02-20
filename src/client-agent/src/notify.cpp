/**
 * @file notify.cpp
 * @brief C++17 implementation of keepalive notification.
 *
 * Replaces notify.c. Encapsulates notification logic in
 * NotifyManager and provides extern "C" trampolines.
 *
 * Copyright (C) 2015, Wazuh Inc.
 */

#include "notify_manager.hpp"

extern "C"
{
#include "md5_op.h"
#include "metadata_provider.h"
#include "sendmsg.h"
#include "state.h"
}

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <sys/stat.h>

namespace agentd
{

    // ── Singleton ────────────────────────────────────────────────────────

    NotifyManager& NotifyManager::instance()
    {
        static NotifyManager inst;
        return inst;
    }

    // ── getsharedfiles ───────────────────────────────────────────────────

    char* NotifyManager::getSharedFiles()
    {
        unsigned int m_size = 64;
        os_md5 md5sum;

        if (OS_MD5_File(SHAREDCFG_FILE, md5sum, OS_TEXT) != 0)
        {
            md5sum[0] = 'x';
            md5sum[1] = '\0';
        }

        char* ret = static_cast<char*>(calloc(m_size + 1, sizeof(char)));
        if (ret)
        {
            snprintf(ret, m_size, "%s", md5sum);
        }
        return ret;
    }

    // ── get_agent_ip ─────────────────────────────────────────────────────

    char* NotifyManager::getAgentIp()
    {
        char agent_ip[IPSIZE + 1] = {'\0'};
        struct sockaddr_storage sas {};
        socklen_t len = sizeof(sas);
        const int err = getsockname(agt->sock, reinterpret_cast<struct sockaddr*>(&sas), &len);

        if (!err)
        {
            switch (sas.ss_family)
            {
                case AF_INET:
                    get_ipv4_string(reinterpret_cast<struct sockaddr_in*>(&sas)->sin_addr, agent_ip, IPSIZE);
                    break;
                case AF_INET6:
                    get_ipv6_string(reinterpret_cast<struct sockaddr_in6*>(&sas)->sin6_addr, agent_ip, IPSIZE);
                    break;
                default: mdebug2("Unknown address family: %d", sas.ss_family); break;
            }
        }
        else
        {
#ifdef WIN32
            mdebug2("getsockname() failed: %s", win_strerror(WSAGetLastError()));
#else
            mdebug2("getsockname() failed: %s", strerror(errno));
#endif
        }

        return strdup(agent_ip);
    }

    // ── clear_merged_hash_cache ──────────────────────────────────────────

    void NotifyManager::clearMergedHashCache()
    {
        os_free(shared_mg_file_hash_);
        shared_mg_file_hash_ = nullptr;
    }

    // ── buildJsonKeepalive (private) ─────────────────────────────────────

    char* NotifyManager::buildJsonKeepalive(const char* agent_ip,
                                            const char* config_sum,
                                            const char* merged_sum,
                                            const char* labels)
    {
        agent_metadata_t metadata = {0};
        bool has_metadata = false;

        // Get metadata from shared memory (may not be available yet)
        if (metadata_provider_get(&metadata) == 0)
        {
            has_metadata = true;
        }
        else
        {
            mdebug2("Metadata not yet available, using minimal keepalive");
        }

        // Build JSON
        cJSON* root = cJSON_CreateObject();
        if (!root)
        {
            if (has_metadata)
            {
                metadata_provider_free_metadata(&metadata);
            }
            return nullptr;
        }

        cJSON_AddStringToObject(root, "version", "1.0");

        // Agent fields
        cJSON* agent_obj = cJSON_CreateObject();
        if (has_metadata)
        {
            if (metadata.agent_id[0])
            {
                cJSON_AddStringToObject(agent_obj, "id", metadata.agent_id);
            }
            if (metadata.agent_name[0])
            {
                cJSON_AddStringToObject(agent_obj, "name", metadata.agent_name);
            }
            if (metadata.agent_version[0])
            {
                cJSON_AddStringToObject(agent_obj, "version", metadata.agent_version);
            }
        }
        if (config_sum && config_sum[0])
        {
            cJSON_AddStringToObject(agent_obj, "config_sum", config_sum);
        }
        if (merged_sum && merged_sum[0])
        {
            cJSON_AddStringToObject(agent_obj, "merged_sum", merged_sum);
        }
        if (agent_ip && agent_ip[0])
        {
            cJSON_AddStringToObject(agent_obj, "ip", agent_ip);
        }
        const char* uname_str = getuname();
        if (uname_str)
        {
            cJSON_AddStringToObject(agent_obj, "uname", uname_str);
        }
        if (labels && labels[0])
        {
            cJSON_AddStringToObject(agent_obj, "labels", labels);
        }

        // Add groups array if available
        if (has_metadata && metadata.groups_count > 0 && metadata.groups)
        {
            cJSON* groups_array = cJSON_CreateArray();
            for (size_t i = 0; i < metadata.groups_count; i++)
            {
                if (metadata.groups[i] && metadata.groups[i][0])
                {
                    cJSON_AddItemToArray(groups_array, cJSON_CreateString(metadata.groups[i]));
                }
            }
            cJSON_AddItemToObject(agent_obj, "groups", groups_array);
        }

        cJSON_AddItemToObject(root, "agent", agent_obj);

        // Host fields (only if metadata available)
        if (has_metadata)
        {
            cJSON* host = cJSON_CreateObject();
            if (metadata.hostname[0])
            {
                cJSON_AddStringToObject(host, "hostname", metadata.hostname);
            }
            if (metadata.architecture[0])
            {
                cJSON_AddStringToObject(host, "architecture", metadata.architecture);
            }

            // Host OS fields
            cJSON* os = cJSON_CreateObject();
            if (metadata.os_name[0])
            {
                cJSON_AddStringToObject(os, "name", metadata.os_name);
            }
            if (metadata.os_version[0])
            {
                cJSON_AddStringToObject(os, "version", metadata.os_version);
            }
            if (metadata.os_platform[0])
            {
                cJSON_AddStringToObject(os, "platform", metadata.os_platform);
            }
            if (metadata.os_type[0])
            {
                cJSON_AddStringToObject(os, "type", metadata.os_type);
            }
            cJSON_AddItemToObject(host, "os", os);
            cJSON_AddItemToObject(root, "host", host);
        }

        // Cluster fields (only if metadata available and cluster info present)
        if (has_metadata)
        {
            cJSON* cluster = cJSON_CreateObject();
            bool has_cluster_info = false;

            if (metadata.cluster_name[0])
            {
                cJSON_AddStringToObject(cluster, "name", metadata.cluster_name);
                has_cluster_info = true;
            }
            if (metadata.cluster_node[0])
            {
                cJSON_AddStringToObject(cluster, "node", metadata.cluster_node);
                has_cluster_info = true;
            }

            if (has_cluster_info)
            {
                cJSON_AddItemToObject(root, "cluster", cluster);
            }
            else
            {
                cJSON_Delete(cluster);
            }
        }

        // Convert to string
        char* json_str = cJSON_PrintUnformatted(root);
        cJSON_Delete(root);
        if (has_metadata)
        {
            metadata_provider_free_metadata(&metadata);
        }

        return json_str;
    }

    // ── run_notify ───────────────────────────────────────────────────────

    void NotifyManager::runNotify()
    {
        char tmp_msg[OS_MAXSTR - OS_HEADER_SIZE + 2];
        static char tmp_labels[OS_MAXSTR - OS_SIZE_2048] = {'\0'};
        static wlabel_t* last_labels_ptr = nullptr;
        os_md5 md5sum = {0};
        time_t curr_time;
        static char agent_ip[IPSIZE + 1] = {'\0'};
        static time_t last_update = 0;

        tmp_msg[OS_MAXSTR - OS_HEADER_SIZE + 1] = '\0';
        curr_time = time(nullptr);

        /* Check if the server has responded */
        if ((curr_time - available_server) > agt->max_time_reconnect_try)
        {
            mwarn(SERVER_UNAV);
            os_setwait();
            w_agentd_state_update(UPDATE_STATUS, reinterpret_cast<void*>(static_cast<intptr_t>(GA_STATUS_NACTIVE)));

            start_agent(0);

            minfo(SERVER_UP);
            os_delwait();
            w_agentd_state_update(UPDATE_STATUS, reinterpret_cast<void*>(static_cast<intptr_t>(GA_STATUS_ACTIVE)));
        }

        /* Check if time has elapsed */
        if ((curr_time - saved_time_) < agt->notify_time)
        {
            return;
        }
        saved_time_ = curr_time;

        mdebug1("Sending agent notification.");

        /* Get uname */
        if (!getuname())
        {
            merror(MEM_ERROR, errno, strerror(errno));
        }

        /* Format labeled data */
        if (agt->labels != last_labels_ptr)
        {
            tmp_labels[0] = '\0';
            if (labels_format(agt->labels, tmp_labels, OS_MAXSTR - OS_SIZE_2048) < 0)
            {
                mwarn("Too large labeled data. Not all labels will be shown in the keep-alive messages.");
            }
            last_labels_ptr = agt->labels;
        }

        /* Get shared files */
        struct stat stat_fd {};
        if (!shared_mg_file_hash_)
        {
            shared_mg_file_hash_ = getSharedFiles();
            if (!shared_mg_file_hash_)
            {
                merror(MEM_ERROR, errno, strerror(errno));
                return;
            }
        }
        else if (w_stat(SHAREDCFG_FILE, &stat_fd) == -1 && ENOENT == errno)
        {
            clearMergedHashCache();
        }

        time_t now = time(nullptr);
        if ((now - last_update) >= agt->main_ip_update_interval)
        {
            last_update = now;
            char* tmp_agent_ip = getAgentIp();

            if (tmp_agent_ip)
            {
                strncpy(agent_ip, tmp_agent_ip, IPSIZE);
                os_free(tmp_agent_ip);
            }
            else
            {
                mdebug1("Cannot update host IP.");
                *agent_ip = '\0';
            }
        }

        /* Compute client.keys MD5 sum if available */
        if ((File_DateofChange(AGENTCONFIG) > 0) && (OS_MD5_File(AGENTCONFIG, md5sum, OS_TEXT) != 0))
        {
            md5sum[0] = '\0';
        }

        /* Create JSON keepalive message */
        char* json_keepalive = buildJsonKeepalive(agent_ip[0] ? agent_ip : nullptr,
                                                  md5sum[0] ? md5sum : nullptr,
                                                  shared_mg_file_hash_,
                                                  tmp_labels[0] ? tmp_labels : nullptr);
        if (!json_keepalive)
        {
            merror("Failed to build JSON keepalive");
            return;
        }

        snprintf(tmp_msg, OS_MAXSTR - OS_HEADER_SIZE, "%s%s", CONTROL_HEADER, json_keepalive);
        os_free(json_keepalive);

        /* Send status message */
        mdebug2("Sending keep alive: %s", tmp_msg);
        send_msg(tmp_msg, -1);

        w_agentd_state_update(UPDATE_KEEPALIVE, static_cast<void*>(&curr_time));
    }

} // namespace agentd

// =====================================================================
//  extern "C" trampolines
// =====================================================================

extern "C"
{

    char* getsharedfiles(void)
    {
        return agentd::NotifyManager::instance().getSharedFiles();
    }

    char* get_agent_ip(void)
    {
        return agentd::NotifyManager::instance().getAgentIp();
    }

    void clear_merged_hash_cache(void)
    {
        agentd::NotifyManager::instance().clearMergedHashCache();
    }

    void run_notify(void)
    {
        agentd::NotifyManager::instance().runNotify();
    }

} // extern "C"
