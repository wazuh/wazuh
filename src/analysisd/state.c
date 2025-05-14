/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef ARGV0
#define ARGV0 "wazuh-analysisd"
#endif

#include "shared.h"
#include "analysisd.h"
#include "state.h"
#include "config.h"
#include "limits.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

analysisd_state_t analysisd_state = {0};
queue_status_t queue_status;
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t agents_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static int w_analysisd_write_state();
static int interval;

extern OSHash *analysisd_agents_state;

/**
 * @brief Get the number of elements divided by the size of queues
 * Values are save in state's variables
 */
static void w_get_queues_size();

/**
 * @brief Obtains analysisd's queues sizes
 * Values are save in state's variables
 */
static void w_get_initial_queues_size();

/**
 * @brief Search or create and return agent state node
 * @param agent_id Id of the agent that corresponds to the node
 * @return analysisd_agent_state_t node
 */
STATIC analysisd_agent_state_t * get_node(const char *agent_id);

/**
 * @brief Clean non active agents from agents state
 * @param sock Wazuh DB socket
 */
STATIC void w_analysisd_clean_agents_state(int *sock);

/**
 * @brief Increment agent decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_agent_decoded_events(const char *agent_id);

/**
 * @brief Increment dbsync decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_dbsync_decoded_events(const char *agent_id);

/**
 * @brief Increment monitor decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_monitor_decoded_events(const char *agent_id);

/**
 * @brief Increment remote decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_remote_decoded_events(const char *agent_id);

/**
 * @brief Increment integrations virustotal decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_integrations_virustotal_decoded_events(const char *agent_id);

/**
 * @brief Increment modules aws decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_aws_decoded_events(const char *agent_id);

/**
 * @brief Increment modules azure decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_azure_decoded_events(const char *agent_id);

/**
 * @brief Increment modules ciscat decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_ciscat_decoded_events(const char *agent_id);

/**
 * @brief Increment modules command decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_command_decoded_events(const char *agent_id);

/**
 * @brief Increment modules docker decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_docker_decoded_events(const char *agent_id);

/**
 * @brief Increment modules gcp decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_gcp_decoded_events(const char *agent_id);

/**
 * @brief Increment modules github decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_github_decoded_events(const char *agent_id);

/**
 * @brief Increment modules office365 decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_office365_decoded_events(const char *agent_id);

/**
 * @brief Increment modules ms-graph decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_ms_graph_decoded_events(const char *agent_id);

/**
 * @brief Increment modules oscap decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_oscap_decoded_events(const char *agent_id);

/**
 * @brief Increment modules osquery decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_osquery_decoded_events(const char *agent_id);

/**
 * @brief Increment modules rootcheck decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_rootcheck_decoded_events(const char *agent_id);

/**
 * @brief Increment modules sca decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_sca_decoded_events(const char *agent_id);

/**
 * @brief Increment modules syscheck decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_syscheck_decoded_events(const char *agent_id);

/**
 * @brief Increment modules syscollector decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_syscollector_decoded_events(const char *agent_id);

/**
 * @brief Increment modules upgrade decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_upgrade_decoded_events(const char *agent_id);

/**
 * @brief Increment modules vulnerability decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_vulnerability_decoded_events(const char *agent_id);

/**
 * @brief Increment modules logcollector eventchannel decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_logcollector_eventchannel_decoded_events(const char *agent_id);

/**
 * @brief Increment modules logcollector eventlog decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_logcollector_eventlog_decoded_events(const char *agent_id);

/**
 * @brief Increment modules logcollector macos decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_logcollector_macos_decoded_events(const char *agent_id);

/**
 * @brief Increment modules logcollector others decoded events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_modules_logcollector_others_decoded_events(const char *agent_id);

/**
 * @brief Increment processed events counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_processed_events(const char *agent_id);

/**
 * @brief Increment alerts written counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_alerts_written(const char *agent_id);

/**
 * @brief Increment archives written counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_archives_written(const char *agent_id);

/**
 * @brief Increment firewall written counter for agents
 * @param agent_id Id of the agent that corresponds to the event
 */
static void w_inc_agents_firewall_written(const char *agent_id);

void * w_analysisd_state_main() {
    interval = getDefine_Int("analysisd", "state_interval", 0, 86400);

    if (!interval) {
        minfo("State file is disabled.");
        return NULL;
    }

    mdebug1("State file updating thread started.");

    w_mutex_lock(&queue_mutex);
    w_get_initial_queues_size();
    w_mutex_unlock(&queue_mutex);

    int sock = -1;
    sock = wdbc_connect();

    while (1) {
        w_analysisd_write_state();
        sleep(interval);
        w_analysisd_clean_agents_state(&sock);
    }

    wdbc_close(&sock);

    return NULL;
}

int w_analysisd_write_state() {
    FILE * fp;
    char path[PATH_MAX - 8];
    char path_temp[PATH_MAX + 1];
    analysisd_state_t state_cpy;
    queue_status_t queue_cpy;

    if (!strcmp(__local_name, "unset")) {
        merror("At write_state(): __local_name is unset.");
        return -1;
    }

    mdebug2("Updating state file.");

    snprintf(path, sizeof(path), OS_PIDFILE "/%s.state", __local_name);
    snprintf(path_temp, sizeof(path_temp), "%s.temp", path);

    if (fp = wfopen(path_temp, "w"), !fp) {
        merror(FOPEN_ERROR, path_temp, errno, strerror(errno));
        return -1;
    }

    w_mutex_lock(&queue_mutex);
    w_get_queues_size();
    memcpy(&queue_cpy, &queue_status, sizeof(queue_status_t));
    w_mutex_unlock(&queue_mutex);

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &analysisd_state, sizeof(analysisd_state_t));
    w_mutex_unlock(&state_mutex);

    fprintf(fp,
        "# State file for %s\n"
        "# THIS FILE WILL BE DEPRECATED IN FUTURE VERSIONS\n"
        "\n"
        "# Total events decoded\n"
        "total_events_decoded='%lu'\n"
        "\n"
        "# Syscheck events decoded\n"
        "syscheck_events_decoded='%lu'\n"
        "\n"
        "# Syscollector events decoded\n"
        "syscollector_events_decoded='%lu'\n"
        "\n"
        "# Rootcheck events decoded\n"
        "rootcheck_events_decoded='%lu'\n"
        "\n"
         "# Security configuration assessment events decoded\n"
        "sca_events_decoded='%lu'\n"
        "\n"
        "# Winevt events decoded\n"
        "winevt_events_decoded='%lu'\n"
        "\n"
        "# Database synchronization messages dispatched\n"
        "dbsync_messages_dispatched='%lu'\n"
        "\n"
        "# Other events decoded\n"
        "other_events_decoded='%lu'\n"
        "\n"
        "# Events processed (Rule matching)\n"
        "events_processed='%lu'\n"
        "\n"
        "# Events received\n"
        "events_received='%lu'\n"
        "\n"
        "# Events dropped\n"
        "events_dropped='%lu'\n"
        "\n"
        "# Alerts written to disk\n"
        "alerts_written='%lu'\n"
        "\n"
        "# Firewall alerts written to disk\n"
        "firewall_written='%u'\n"
        "\n"
        "# FTS alerts written to disk\n"
        "fts_written='%u'\n"
        "\n"
        "# Syscheck queue\n"
        "syscheck_queue_usage='%.2f'\n"
        "\n"
        "# Syscheck queue size\n"
        "syscheck_queue_size='%zu'\n"
        "\n"
        "# Syscollector queue\n"
        "syscollector_queue_usage='%.2f'\n"
        "\n"
        "# Syscollector queue size\n"
        "syscollector_queue_size='%zu'\n"
        "\n"
        "# Rootcheck queue\n"
        "rootcheck_queue_usage='%.2f'\n"
        "\n"
        "# Rootcheck queue size\n"
        "rootcheck_queue_size='%zu'\n"
        "\n"
        "# Security configuration assessment queue\n"
        "sca_queue_usage='%.2f'\n"
        "\n"
        "# Security configuration assessment queue size\n"
        "sca_queue_size='%zu'\n"
        "\n"
        "# Hostinfo queue\n"
        "hostinfo_queue_usage='%.2f'\n"
        "\n"
        "# Hostinfo queue size\n"
        "hostinfo_queue_size='%zu'\n"
        "\n"
        "# Winevt queue\n"
        "winevt_queue_usage='%.2f'\n"
        "\n"
        "# Winevt queue size\n"
        "winevt_queue_size='%zu'\n"
        "\n"
        "# Database synchronization message queue\n"
        "dbsync_queue_usage='%.2f'\n"
        "\n"
        "# Database synchronization message queue size\n"
        "dbsync_queue_size='%zu'\n"
        "\n"
        "# Upgrade module message queue\n"
        "upgrade_queue_usage='%.2f'\n"
        "\n"
        "# Upgrade module message queue size\n"
        "upgrade_queue_size='%zu'\n"
        "\n"
        "# Event queue\n"
        "event_queue_usage='%.2f'\n"
        "\n"
        "# Event queue size\n"
        "event_queue_size='%zu'\n"
        "\n"
        "# Rule matching queue\n"
        "rule_matching_queue_usage='%.2f'\n"
        "\n"
        "# Rule matching queue size\n"
        "rule_matching_queue_size='%zu'\n"
        "\n"
        "# Alerts log queue\n"
        "alerts_queue_usage='%.2f'\n"
        "\n"
        "# Alerts log queue size\n"
        "alerts_queue_size='%zu'\n"
        "\n"
        "# Firewall log queue\n"
        "firewall_queue_usage='%.2f'\n"
        "\n"
        "# Firewall log queue size\n"
        "firewall_queue_size='%zu'\n"
        "\n"
        "# Statistical log queue\n"
        "statistical_queue_usage='%.2f'\n"
        "\n"
        "# Statistical log queue size\n"
        "statistical_queue_size='%zu'\n"
        "\n"
        "# Archives log queue\n"
        "archives_queue_usage='%.2f'\n"
        "\n"
        "# Archives log queue size\n"
        "archives_queue_size='%zu'\n"
        "\n",
        __local_name,
        state_cpy.events_decoded_breakdown.modules.syscheck +
        state_cpy.events_decoded_breakdown.modules.syscollector +
        state_cpy.events_decoded_breakdown.modules.rootcheck +
        state_cpy.events_decoded_breakdown.modules.sca +
        state_cpy.events_decoded_breakdown.modules.logcollector.eventchannel +
        state_cpy.events_decoded_breakdown.dbsync +
        state_cpy.events_decoded_breakdown.modules.upgrade +
        state_cpy.events_decoded_breakdown.modules.ciscat +
        state_cpy.events_decoded_breakdown.syslog +
        state_cpy.events_decoded_breakdown.modules.logcollector.others,
        state_cpy.events_decoded_breakdown.modules.syscheck,
        state_cpy.events_decoded_breakdown.modules.syscollector,
        state_cpy.events_decoded_breakdown.modules.rootcheck,
        state_cpy.events_decoded_breakdown.modules.sca,
        state_cpy.events_decoded_breakdown.modules.logcollector.eventchannel,
        state_cpy.events_decoded_breakdown.dbsync,
        state_cpy.events_decoded_breakdown.modules.upgrade +
        state_cpy.events_decoded_breakdown.modules.ciscat +
        state_cpy.events_decoded_breakdown.syslog +
        state_cpy.events_decoded_breakdown.modules.logcollector.others,
        state_cpy.events_processed,
        state_cpy.events_received,
        state_cpy.events_dropped_breakdown.modules.syscheck +
        state_cpy.events_dropped_breakdown.modules.syscollector +
        state_cpy.events_dropped_breakdown.modules.rootcheck +
        state_cpy.events_dropped_breakdown.modules.sca +
        state_cpy.events_dropped_breakdown.modules.logcollector.eventchannel +
        state_cpy.events_dropped_breakdown.dbsync +
        state_cpy.events_dropped_breakdown.modules.upgrade +
        state_cpy.events_dropped_breakdown.modules.ciscat +
        state_cpy.events_dropped_breakdown.syslog +
        state_cpy.events_dropped_breakdown.modules.logcollector.others,
        state_cpy.events_written_breakdown.alerts_written,
        state_cpy.events_written_breakdown.firewall_written,
        state_cpy.events_written_breakdown.fts_written,
        queue_status.syscheck_queue_usage,
        queue_status.syscheck_queue_size,
        queue_status.syscollector_queue_usage,
        queue_status.syscollector_queue_size,
        queue_status.rootcheck_queue_usage,
        queue_status.rootcheck_queue_size,
        queue_status.sca_queue_usage,
        queue_status.sca_queue_size,
        queue_status.hostinfo_queue_usage,
        queue_status.hostinfo_queue_size,
        queue_status.winevt_queue_usage,
        queue_status.winevt_queue_size,
        queue_status.dbsync_queue_usage, queue_status.dbsync_queue_size,
        queue_status.upgrade_queue_usage, queue_status.upgrade_queue_size,
        queue_status.events_queue_usage, queue_status.events_queue_size,
        queue_status.processed_queue_usage,
        queue_status.processed_queue_size,
        queue_status.alerts_queue_usage,
        queue_status.alerts_queue_size,
        queue_status.firewall_queue_usage,
        queue_status.firewall_queue_size,
        queue_status.stats_queue_usage,
        queue_status.stats_queue_size,
        queue_status.archives_queue_usage,
        queue_status.archives_queue_size);

    fclose(fp);

    if (rename(path_temp, path) < 0) {
        merror("Renaming %s to %s: %s", path_temp, path, strerror(errno));
        if (unlink(path_temp) < 0) {
            merror("Deleting %s: %s", path_temp, strerror(errno));
        }
       return -1;
    }

   return 0;
}

void w_get_queues_size() {
    queue_status.syscheck_queue_usage = queue_get_percentage_ex(decode_queue_syscheck_input);
    queue_status.syscollector_queue_usage = queue_get_percentage_ex(decode_queue_syscollector_input);
    queue_status.rootcheck_queue_usage = queue_get_percentage_ex(decode_queue_rootcheck_input);
    queue_status.sca_queue_usage = queue_get_percentage_ex(decode_queue_sca_input);
    queue_status.hostinfo_queue_usage = queue_get_percentage_ex(decode_queue_hostinfo_input);
    queue_status.winevt_queue_usage = queue_get_percentage_ex(decode_queue_winevt_input);
    queue_status.dbsync_queue_usage = queue_get_percentage_ex(dispatch_dbsync_input);
    queue_status.upgrade_queue_usage = queue_get_percentage_ex(upgrade_module_input);
    queue_status.events_queue_usage = queue_get_percentage_ex(decode_queue_event_input);
    queue_status.processed_queue_usage = queue_get_percentage_ex(decode_queue_event_output);
    queue_status.alerts_queue_usage = queue_get_percentage_ex(writer_queue_log);
    queue_status.archives_queue_usage = queue_get_percentage_ex(writer_queue);
    queue_status.firewall_queue_usage = queue_get_percentage_ex(writer_queue_log_firewall);
    queue_status.fts_queue_usage = queue_get_percentage_ex(writer_queue_log_fts);
    queue_status.stats_queue_usage = queue_get_percentage_ex(writer_queue_log_statistical);
}

void w_get_initial_queues_size() {
    queue_status.syscheck_queue_size = decode_queue_syscheck_input->size;
    queue_status.syscollector_queue_size = decode_queue_syscollector_input->size;
    queue_status.rootcheck_queue_size = decode_queue_rootcheck_input->size;
    queue_status.sca_queue_size = decode_queue_sca_input->size;
    queue_status.hostinfo_queue_size = decode_queue_hostinfo_input->size;
    queue_status.winevt_queue_size = decode_queue_winevt_input->size;
    queue_status.dbsync_queue_size = dispatch_dbsync_input->size;
    queue_status.upgrade_queue_size = upgrade_module_input->size;
    queue_status.events_queue_size = decode_queue_event_input->size;
    queue_status.processed_queue_size = decode_queue_event_output->size;
    queue_status.alerts_queue_size = writer_queue_log->size;
    queue_status.archives_queue_size = writer_queue->size;
    queue_status.firewall_queue_size = writer_queue_log_firewall->size;
    queue_status.fts_queue_size = writer_queue_log_fts->size;
    queue_status.stats_queue_size = writer_queue_log_statistical->size;
}

STATIC analysisd_agent_state_t * get_node(const char *agent_id) {
    analysisd_agent_state_t * agent_state = (analysisd_agent_state_t *) OSHash_Get_ex(analysisd_agents_state, agent_id);

    if(agent_state != NULL) {
        return agent_state;
    } else {
        os_calloc(1, sizeof(analysisd_agent_state_t), agent_state);
        agent_state->uptime = time(NULL);
        OSHash_Add_ex(analysisd_agents_state, agent_id, agent_state);
        return agent_state;
    }
}

STATIC void w_analysisd_clean_agents_state(int *sock) {
    int *active_agents = NULL;
    OSHashNode *hash_node;
    unsigned int inode_it = 0;

    hash_node = OSHash_Begin(analysisd_agents_state, &inode_it);

    if (hash_node == NULL) {
        return;
    }

    if (active_agents = wdb_get_agents_ids_of_current_node(AGENT_CS_ACTIVE, sock, 0, -1), active_agents == NULL) {
        return;
    }

    char *agent_id = NULL;
    analysisd_agent_state_t * agent_state = NULL;

    while (hash_node) {
        agent_id = hash_node->key;

        hash_node = OSHash_Next(analysisd_agents_state, &inode_it, hash_node);

        int exist = 0;
        for (size_t i = 0; active_agents[i] != -1; i++) {
            if (atoi(agent_id) == active_agents[i] ) {
                exist = 1;
                break;
            }
        }

        if (exist == 0) {
            agent_state = (analysisd_agent_state_t *)OSHash_Delete_ex(analysisd_agents_state, agent_id);
            os_free(agent_state);
        }
    }

    os_free(active_agents);
    return;
}

static void w_inc_agents_agent_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.agent++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_dbsync_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.dbsync++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_monitor_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.monitor++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_remote_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.remote++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_integrations_virustotal_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.integrations.virustotal++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_aws_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.aws++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_azure_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.azure++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_ciscat_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.ciscat++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_command_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.command++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_docker_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.docker++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_gcp_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.gcp++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_github_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.github++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_office365_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.office365++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_ms_graph_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.ms_graph++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_oscap_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.oscap++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_osquery_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.osquery++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_rootcheck_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.rootcheck++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_sca_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.sca++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_syscheck_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.syscheck++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_syscollector_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.syscollector++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_upgrade_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.upgrade++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_vulnerability_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.vulnerability++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_logcollector_eventchannel_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.logcollector.eventchannel++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_logcollector_eventlog_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.logcollector.eventlog++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_logcollector_macos_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.logcollector.macos++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_modules_logcollector_others_decoded_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_decoded_breakdown.modules.logcollector.others++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_processed_events(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->events_processed++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_alerts_written(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->alerts_written++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_archives_written(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->archives_written++;
    w_mutex_unlock(&agents_state_mutex);
}

static void w_inc_agents_firewall_written(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    analysisd_agent_state_t *agent_node = get_node(agent_id);
    agent_node->firewall_written++;
    w_mutex_unlock(&agents_state_mutex);
}

void w_add_recv(unsigned long bytes) {
    w_mutex_lock(&state_mutex);
    analysisd_state.received_bytes += bytes;
    w_mutex_unlock(&state_mutex);
}

void w_inc_received_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_received++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_decoded_by_component_events(const char *component, const char *agent_id) {
    if (component != NULL) {
        if (!strcmp(component, "wazuh-agent")) {
            w_inc_agent_decoded_events(agent_id);
        } else if (!strcmp(component, "wazuh-agentlessd")) {
            w_inc_agentless_decoded_events(agent_id);
        } else if (!strcmp(component, "wazuh-monitord")) {
            w_inc_monitor_decoded_events(agent_id);
        } else if (!strcmp(component, "wazuh-remoted")) {
            w_inc_remote_decoded_events(agent_id);
        } else if (!strcmp(component, "virustotal")) {
            w_inc_integrations_virustotal_decoded_events(agent_id);
        } else if (!strcmp(component, "aws-s3") || !strcmp(component, "Wazuh-AWS")) {
            w_inc_modules_aws_decoded_events(agent_id);
        } else if (!strcmp(component, "azure-logs") || !strcmp(component, "Azure")) {
            w_inc_modules_azure_decoded_events(agent_id);
        } else if (!strcmp(component, "cis-cat") || !strcmp(component, "wodle_cis-cat")) {
            w_inc_modules_ciscat_decoded_events(agent_id);
        } else if (!strcmp(component, "command") || !strncmp(component, "command_", 8)) {
            w_inc_modules_command_decoded_events(agent_id);
        } else if (!strcmp(component, "docker-listener") || !strcmp(component, "Wazuh-Docker")) {
            w_inc_modules_docker_decoded_events(agent_id);
        } else if (!strcmp(component, "gcp-pubsub") || !strcmp(component, "gcp-bucket") || !strcmp(component, "Wazuh-GCloud")) {
            w_inc_modules_gcp_decoded_events(agent_id);
        } else if (!strcmp(component, "github")) {
            w_inc_modules_github_decoded_events(agent_id);
        } else if (!strcmp(component, "office365")) {
            w_inc_modules_office365_decoded_events(agent_id);
        } else if (!strcmp(component, "ms-graph")) {
            w_inc_modules_ms_graph_decoded_events(agent_id);
        } else if (!strcmp(component, "open-scap") || !strcmp(component, "wodle_open-scap")) {
            w_inc_modules_oscap_decoded_events(agent_id);
        } else if (!strcmp(component, "osquery")) {
            w_inc_modules_osquery_decoded_events(agent_id);
        } else if (!strcmp(component, "rootcheck")) {
            w_inc_modules_rootcheck_decoded_events(agent_id);
        } else if (!strcmp(component, "sca")) {
            w_inc_modules_sca_decoded_events(agent_id);
        } else if (!strcmp(component, "syscheck")) {
            w_inc_modules_syscheck_decoded_events(agent_id);
        } else if (!strcmp(component, "syscollector")) {
            w_inc_modules_syscollector_decoded_events(agent_id);
        } else if (!strcmp(component, "agent-upgrade")) {
            w_inc_modules_upgrade_decoded_events(agent_id);
        } else if (!strcmp(component, "vulnerability-detector")) {
            w_inc_modules_vulnerability_decoded_events(agent_id);
        } else if (!strcmp(component, "macos")) {
            w_inc_modules_logcollector_macos_decoded_events(agent_id);
        } else if (!strcmp(component, "WinEvtLog")) {
            w_inc_modules_logcollector_eventlog_decoded_events(agent_id);
        } else {
            w_inc_modules_logcollector_others_decoded_events(agent_id);
        }
    }
}

void w_inc_agent_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.agent++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_agent_decoded_events(agent_id);
    }
}

void w_inc_agentless_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.agentless++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_dbsync_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.dbsync++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_dbsync_decoded_events(agent_id);
    }
}

void w_inc_monitor_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.monitor++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_monitor_decoded_events(agent_id);
    }
}

void w_inc_remote_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.remote++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_remote_decoded_events(agent_id);
    }
}

void w_inc_syslog_decoded_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.syslog++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_integrations_virustotal_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.integrations.virustotal++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_integrations_virustotal_decoded_events(agent_id);
    }
}

void w_inc_modules_aws_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.aws++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_aws_decoded_events(agent_id);
    }
}

void w_inc_modules_azure_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.azure++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_azure_decoded_events(agent_id);
    }
}

void w_inc_modules_ciscat_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.ciscat++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_ciscat_decoded_events(agent_id);
    }
}

void w_inc_modules_command_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.command++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_command_decoded_events(agent_id);
    }
}

void w_inc_modules_docker_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.docker++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_docker_decoded_events(agent_id);
    }
}

void w_inc_modules_gcp_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.gcp++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_gcp_decoded_events(agent_id);
    }
}

void w_inc_modules_github_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.github++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_github_decoded_events(agent_id);
    }
}

void w_inc_modules_office365_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.office365++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_office365_decoded_events(agent_id);
    }
}

void w_inc_modules_ms_graph_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.ms_graph++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_ms_graph_decoded_events(agent_id);
    }
}

void w_inc_modules_oscap_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.oscap++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_oscap_decoded_events(agent_id);
    }
}

void w_inc_modules_osquery_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.osquery++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_osquery_decoded_events(agent_id);
    }
}

void w_inc_modules_rootcheck_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.rootcheck++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_rootcheck_decoded_events(agent_id);
    }
}

void w_inc_modules_sca_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.sca++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_sca_decoded_events(agent_id);
    }
}

void w_inc_modules_syscheck_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.syscheck++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_syscheck_decoded_events(agent_id);
    }
}

void w_inc_modules_syscollector_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.syscollector++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_syscollector_decoded_events(agent_id);
    }
}

void w_inc_modules_upgrade_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.upgrade++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_upgrade_decoded_events(agent_id);
    }
}

void w_inc_modules_vulnerability_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.vulnerability++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_vulnerability_decoded_events(agent_id);
    }
}

void w_inc_modules_logcollector_eventchannel_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.logcollector.eventchannel++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_logcollector_eventchannel_decoded_events(agent_id);
    }
}

void w_inc_modules_logcollector_eventlog_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.logcollector.eventlog++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_logcollector_eventlog_decoded_events(agent_id);
    }
}

void w_inc_modules_logcollector_macos_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.logcollector.macos++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_logcollector_macos_decoded_events(agent_id);
    }
}

void w_inc_modules_logcollector_others_decoded_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_decoded_breakdown.modules.logcollector.others++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_modules_logcollector_others_decoded_events(agent_id);
    }
}

void w_inc_dropped_by_component_events(const char *component) {
    if (component != NULL) {
        if (!strcmp(component, "wazuh-agent")) {
            w_inc_agent_dropped_events();
        } else if (!strcmp(component, "wazuh-agentlessd")) {
            w_inc_agentless_dropped_events();
        } else if (!strcmp(component, "wazuh-monitord")) {
            w_inc_monitor_dropped_events();
        } else if (!strcmp(component, "wazuh-remoted")) {
            w_inc_remote_dropped_events();
        } else if (!strcmp(component, "virustotal")) {
            w_inc_integrations_virustotal_dropped_events();
        } else if (!strcmp(component, "aws-s3") || !strcmp(component, "Wazuh-AWS")) {
            w_inc_modules_aws_dropped_events();
        } else if (!strcmp(component, "azure-logs") || !strcmp(component, "Azure")) {
            w_inc_modules_azure_dropped_events();
        } else if (!strcmp(component, "cis-cat") || !strcmp(component, "wodle_cis-cat")) {
            w_inc_modules_ciscat_dropped_events();
        } else if (!strcmp(component, "command") || !strncmp(component, "command_", 8)) {
            w_inc_modules_command_dropped_events();
        } else if (!strcmp(component, "docker-listener") || !strcmp(component, "Wazuh-Docker")) {
            w_inc_modules_docker_dropped_events();
        } else if (!strcmp(component, "gcp-pubsub") || !strcmp(component, "gcp-bucket") || !strcmp(component, "Wazuh-GCloud")) {
            w_inc_modules_gcp_dropped_events();
        } else if (!strcmp(component, "github")) {
            w_inc_modules_github_dropped_events();
        } else if (!strcmp(component, "office365")) {
            w_inc_modules_office365_dropped_events();
        } else if (!strcmp(component, "ms-graph")) {
            w_inc_modules_ms_graph_dropped_events();
        } else if (!strcmp(component, "open-scap") || !strcmp(component, "wodle_open-scap")) {
            w_inc_modules_oscap_dropped_events();
        } else if (!strcmp(component, "osquery")) {
            w_inc_modules_osquery_dropped_events();
        } else if (!strcmp(component, "rootcheck")) {
            w_inc_modules_rootcheck_dropped_events();
        } else if (!strcmp(component, "sca")) {
            w_inc_modules_sca_dropped_events();
        } else if (!strcmp(component, "syscheck")) {
            w_inc_modules_syscheck_dropped_events();
        } else if (!strcmp(component, "syscollector")) {
            w_inc_modules_syscollector_dropped_events();
        } else if (!strcmp(component, "agent-upgrade")) {
            w_inc_modules_upgrade_dropped_events();
        } else if (!strcmp(component, "vulnerability-detector")) {
            w_inc_modules_vulnerability_dropped_events();
        } else if (!strcmp(component, "macos")) {
            w_inc_modules_logcollector_macos_dropped_events();
        } else if (!strcmp(component, "WinEvtLog")) {
            w_inc_modules_logcollector_eventlog_dropped_events();
        } else {
            w_inc_modules_logcollector_others_dropped_events();
        }
    }
}

void w_inc_agent_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.agent++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_agentless_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.agentless++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_dbsync_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.dbsync++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_monitor_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.monitor++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_remote_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.remote++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_syslog_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.syslog++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_integrations_virustotal_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.integrations.virustotal++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_aws_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.aws++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_azure_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.azure++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_ciscat_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.ciscat++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_command_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.command++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_docker_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.docker++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_gcp_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.gcp++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_github_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.github++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_office365_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.office365++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_ms_graph_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.ms_graph++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_oscap_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.oscap++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_osquery_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.osquery++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_rootcheck_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.rootcheck++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_sca_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.sca++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_syscheck_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.syscheck++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_syscollector_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.syscollector++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_upgrade_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.upgrade++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_vulnerability_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.vulnerability++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_logcollector_eventchannel_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.logcollector.eventchannel++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_logcollector_eventlog_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.logcollector.eventlog++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_logcollector_macos_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.logcollector.macos++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_modules_logcollector_others_dropped_events() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_dropped_breakdown.modules.logcollector.others++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_processed_events(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_processed++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_processed_events(agent_id);
    }
}

void w_inc_alerts_written(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_written_breakdown.alerts_written++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_alerts_written(agent_id);
    }
}

void w_inc_archives_written(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_written_breakdown.archives_written++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_archives_written(agent_id);
    }
}

void w_inc_firewall_written(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_written_breakdown.firewall_written++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL && strcmp(agent_id, "000") != 0) {
        w_inc_agents_firewall_written(agent_id);
    }
}

void w_inc_fts_written() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_written_breakdown.fts_written++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_stats_written() {
    w_mutex_lock(&state_mutex);
    analysisd_state.events_written_breakdown.stats_written++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_eps_events_dropped() {
    w_mutex_lock(&state_mutex);
    analysisd_state.eps_state_breakdown.events_dropped++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_eps_events_dropped_not_eps() {
    w_mutex_lock(&state_mutex);
    analysisd_state.eps_state_breakdown.events_dropped_not_eps++;
    w_mutex_unlock(&state_mutex);
}

void w_inc_eps_seconds_over_limit() {
    w_mutex_lock(&state_mutex);
    analysisd_state.eps_state_breakdown.seconds_over_limit++;
    w_mutex_unlock(&state_mutex);
}

void w_set_available_credits_prev(unsigned int credits) {
    w_mutex_lock(&state_mutex);
    analysisd_state.eps_state_breakdown.available_credits_prev = credits;
    w_mutex_unlock(&state_mutex);
}

cJSON* asys_create_state_json() {
    analysisd_state_t state_cpy;
    queue_status_t queue_cpy;

    w_mutex_lock(&queue_mutex);
    w_get_queues_size();
    memcpy(&queue_cpy, &queue_status, sizeof(queue_status_t));
    w_mutex_unlock(&queue_mutex);

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &analysisd_state, sizeof(analysisd_state_t));
    w_mutex_unlock(&state_mutex);

    cJSON *asys_state_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(asys_state_json, "uptime", state_cpy.uptime);
    cJSON_AddNumberToObject(asys_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(asys_state_json, "name", ARGV0);

    cJSON *_metrics = cJSON_CreateObject();
    cJSON_AddItemToObject(asys_state_json, "metrics", _metrics);

    // Fields within metrics are sorted alphabetically

    cJSON *_bytes = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "bytes", _bytes);

    cJSON_AddNumberToObject(_bytes, "received", state_cpy.received_bytes);

    if (Config.eps.maximum > 0 && Config.eps.timeframe > 0) {
        unsigned int available_credits = 0;

        cJSON *_eps = cJSON_CreateObject();
        cJSON_AddItemToObject(_metrics, "eps", _eps);

        limit_reached(&available_credits);

        cJSON_AddNumberToObject(_eps, "available_credits", available_credits);
        cJSON_AddNumberToObject(_eps, "available_credits_prev", state_cpy.eps_state_breakdown.available_credits_prev);
        cJSON_AddNumberToObject(_eps, "events_dropped", state_cpy.eps_state_breakdown.events_dropped);
        cJSON_AddNumberToObject(_eps, "events_dropped_not_eps", state_cpy.eps_state_breakdown.events_dropped_not_eps);
        cJSON_AddNumberToObject(_eps, "seconds_over_limit", state_cpy.eps_state_breakdown.seconds_over_limit);
    }

    cJSON *_events = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "events", _events);

    cJSON_AddNumberToObject(_events, "processed", state_cpy.events_processed);

    cJSON_AddNumberToObject(_events, "received", state_cpy.events_received);

    cJSON *_received_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_events, "received_breakdown", _received_breakdown);

    cJSON *_decoded_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received_breakdown, "decoded_breakdown", _decoded_breakdown);

    cJSON_AddNumberToObject(_decoded_breakdown, "agent", state_cpy.events_decoded_breakdown.agent);
    cJSON_AddNumberToObject(_decoded_breakdown, "agentless", state_cpy.events_decoded_breakdown.agentless);
    cJSON_AddNumberToObject(_decoded_breakdown, "dbsync", state_cpy.events_decoded_breakdown.dbsync);

    cJSON *_decoded_integrations = cJSON_CreateObject();
    cJSON_AddItemToObject(_decoded_breakdown, "integrations_breakdown", _decoded_integrations);

    cJSON_AddNumberToObject(_decoded_integrations, "virustotal", state_cpy.events_decoded_breakdown.integrations.virustotal);

    cJSON *_decoded_modules = cJSON_CreateObject();
    cJSON_AddItemToObject(_decoded_breakdown, "modules_breakdown", _decoded_modules);

    cJSON_AddNumberToObject(_decoded_modules, "aws", state_cpy.events_decoded_breakdown.modules.aws);
    cJSON_AddNumberToObject(_decoded_modules, "azure", state_cpy.events_decoded_breakdown.modules.azure);
    cJSON_AddNumberToObject(_decoded_modules, "ciscat", state_cpy.events_decoded_breakdown.modules.ciscat);
    cJSON_AddNumberToObject(_decoded_modules, "command", state_cpy.events_decoded_breakdown.modules.command);
    cJSON_AddNumberToObject(_decoded_modules, "docker", state_cpy.events_decoded_breakdown.modules.docker);
    cJSON_AddNumberToObject(_decoded_modules, "gcp", state_cpy.events_decoded_breakdown.modules.gcp);
    cJSON_AddNumberToObject(_decoded_modules, "github", state_cpy.events_decoded_breakdown.modules.github);

    cJSON *_decoded_modules_logcollector = cJSON_CreateObject();
    cJSON_AddItemToObject(_decoded_modules, "logcollector_breakdown", _decoded_modules_logcollector);

    cJSON_AddNumberToObject(_decoded_modules_logcollector, "eventchannel", state_cpy.events_decoded_breakdown.modules.logcollector.eventchannel);
    cJSON_AddNumberToObject(_decoded_modules_logcollector, "eventlog", state_cpy.events_decoded_breakdown.modules.logcollector.eventlog);
    cJSON_AddNumberToObject(_decoded_modules_logcollector, "macos", state_cpy.events_decoded_breakdown.modules.logcollector.macos);
    cJSON_AddNumberToObject(_decoded_modules_logcollector, "others", state_cpy.events_decoded_breakdown.modules.logcollector.others);

    cJSON_AddNumberToObject(_decoded_modules, "office365", state_cpy.events_decoded_breakdown.modules.office365);
    cJSON_AddNumberToObject(_decoded_modules, "ms-graph", state_cpy.events_decoded_breakdown.modules.ms_graph);
    cJSON_AddNumberToObject(_decoded_modules, "oscap", state_cpy.events_decoded_breakdown.modules.oscap);
    cJSON_AddNumberToObject(_decoded_modules, "osquery", state_cpy.events_decoded_breakdown.modules.osquery);
    cJSON_AddNumberToObject(_decoded_modules, "rootcheck", state_cpy.events_decoded_breakdown.modules.rootcheck);
    cJSON_AddNumberToObject(_decoded_modules, "sca", state_cpy.events_decoded_breakdown.modules.sca);
    cJSON_AddNumberToObject(_decoded_modules, "syscheck", state_cpy.events_decoded_breakdown.modules.syscheck);
    cJSON_AddNumberToObject(_decoded_modules, "syscollector", state_cpy.events_decoded_breakdown.modules.syscollector);
    cJSON_AddNumberToObject(_decoded_modules, "upgrade", state_cpy.events_decoded_breakdown.modules.upgrade);
    cJSON_AddNumberToObject(_decoded_modules, "vulnerability", state_cpy.events_decoded_breakdown.modules.vulnerability);

    cJSON_AddNumberToObject(_decoded_breakdown, "monitor", state_cpy.events_decoded_breakdown.monitor);
    cJSON_AddNumberToObject(_decoded_breakdown, "remote", state_cpy.events_decoded_breakdown.remote);
    cJSON_AddNumberToObject(_decoded_breakdown, "syslog", state_cpy.events_decoded_breakdown.syslog);

    cJSON *_dropped_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received_breakdown, "dropped_breakdown", _dropped_breakdown);

    cJSON_AddNumberToObject(_dropped_breakdown, "agent", state_cpy.events_dropped_breakdown.agent);
    cJSON_AddNumberToObject(_dropped_breakdown, "agentless", state_cpy.events_dropped_breakdown.agentless);
    cJSON_AddNumberToObject(_dropped_breakdown, "dbsync", state_cpy.events_dropped_breakdown.dbsync);

    cJSON *_dropped_integrations = cJSON_CreateObject();
    cJSON_AddItemToObject(_dropped_breakdown, "integrations_breakdown", _dropped_integrations);

    cJSON_AddNumberToObject(_dropped_integrations, "virustotal", state_cpy.events_dropped_breakdown.integrations.virustotal);

    cJSON *_dropped_modules = cJSON_CreateObject();
    cJSON_AddItemToObject(_dropped_breakdown, "modules_breakdown", _dropped_modules);

    cJSON_AddNumberToObject(_dropped_modules, "aws", state_cpy.events_dropped_breakdown.modules.aws);
    cJSON_AddNumberToObject(_dropped_modules, "azure", state_cpy.events_dropped_breakdown.modules.azure);
    cJSON_AddNumberToObject(_dropped_modules, "ciscat", state_cpy.events_dropped_breakdown.modules.ciscat);
    cJSON_AddNumberToObject(_dropped_modules, "command", state_cpy.events_dropped_breakdown.modules.command);
    cJSON_AddNumberToObject(_dropped_modules, "docker", state_cpy.events_dropped_breakdown.modules.docker);
    cJSON_AddNumberToObject(_dropped_modules, "gcp", state_cpy.events_dropped_breakdown.modules.gcp);
    cJSON_AddNumberToObject(_dropped_modules, "github", state_cpy.events_dropped_breakdown.modules.github);

    cJSON *_dropped_modules_logcollector = cJSON_CreateObject();
    cJSON_AddItemToObject(_dropped_modules, "logcollector_breakdown", _dropped_modules_logcollector);

    cJSON_AddNumberToObject(_dropped_modules_logcollector, "eventchannel", state_cpy.events_dropped_breakdown.modules.logcollector.eventchannel);
    cJSON_AddNumberToObject(_dropped_modules_logcollector, "eventlog", state_cpy.events_dropped_breakdown.modules.logcollector.eventlog);
    cJSON_AddNumberToObject(_dropped_modules_logcollector, "macos", state_cpy.events_dropped_breakdown.modules.logcollector.macos);
    cJSON_AddNumberToObject(_dropped_modules_logcollector, "others", state_cpy.events_dropped_breakdown.modules.logcollector.others);

    cJSON_AddNumberToObject(_dropped_modules, "office365", state_cpy.events_dropped_breakdown.modules.office365);
    cJSON_AddNumberToObject(_dropped_modules, "ms-graph", state_cpy.events_dropped_breakdown.modules.ms_graph);
    cJSON_AddNumberToObject(_dropped_modules, "oscap", state_cpy.events_dropped_breakdown.modules.oscap);
    cJSON_AddNumberToObject(_dropped_modules, "osquery", state_cpy.events_dropped_breakdown.modules.osquery);
    cJSON_AddNumberToObject(_dropped_modules, "rootcheck", state_cpy.events_dropped_breakdown.modules.rootcheck);
    cJSON_AddNumberToObject(_dropped_modules, "sca", state_cpy.events_dropped_breakdown.modules.sca);
    cJSON_AddNumberToObject(_dropped_modules, "syscheck", state_cpy.events_dropped_breakdown.modules.syscheck);
    cJSON_AddNumberToObject(_dropped_modules, "syscollector", state_cpy.events_dropped_breakdown.modules.syscollector);
    cJSON_AddNumberToObject(_dropped_modules, "upgrade", state_cpy.events_dropped_breakdown.modules.upgrade);
    cJSON_AddNumberToObject(_dropped_modules, "vulnerability", state_cpy.events_dropped_breakdown.modules.vulnerability);

    cJSON_AddNumberToObject(_dropped_breakdown, "monitor", state_cpy.events_dropped_breakdown.monitor);
    cJSON_AddNumberToObject(_dropped_breakdown, "remote", state_cpy.events_dropped_breakdown.remote);
    cJSON_AddNumberToObject(_dropped_breakdown, "syslog", state_cpy.events_dropped_breakdown.syslog);

    cJSON *_written_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_events, "written_breakdown", _written_breakdown);

    cJSON_AddNumberToObject(_written_breakdown, "alerts", state_cpy.events_written_breakdown.alerts_written);
    cJSON_AddNumberToObject(_written_breakdown, "archives", state_cpy.events_written_breakdown.archives_written);
    cJSON_AddNumberToObject(_written_breakdown, "firewall", state_cpy.events_written_breakdown.firewall_written);
    cJSON_AddNumberToObject(_written_breakdown, "fts", state_cpy.events_written_breakdown.fts_written);
    cJSON_AddNumberToObject(_written_breakdown, "stats", state_cpy.events_written_breakdown.stats_written);

    cJSON *_queues = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "queues", _queues);

    cJSON *_alerts_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "alerts", _alerts_q);

    cJSON_AddNumberToObject(_alerts_q, "size", queue_cpy.alerts_queue_size);
    cJSON_AddNumberToObject(_alerts_q, "usage", queue_cpy.alerts_queue_usage);

    cJSON *_archives_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "archives", _archives_q);

    cJSON_AddNumberToObject(_archives_q, "size", queue_cpy.archives_queue_size);
    cJSON_AddNumberToObject(_archives_q, "usage", queue_cpy.archives_queue_usage);

    cJSON *_dbsync_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "dbsync", _dbsync_q);

    cJSON_AddNumberToObject(_dbsync_q, "size", queue_cpy.dbsync_queue_size);
    cJSON_AddNumberToObject(_dbsync_q, "usage", queue_cpy.dbsync_queue_usage);

    cJSON *_eventchannel_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "eventchannel", _eventchannel_q);

    cJSON_AddNumberToObject(_eventchannel_q, "size", queue_cpy.winevt_queue_size);
    cJSON_AddNumberToObject(_eventchannel_q, "usage", queue_cpy.winevt_queue_usage);

    cJSON *_firewall_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "firewall", _firewall_q);

    cJSON_AddNumberToObject(_firewall_q, "size", queue_cpy.firewall_queue_size);
    cJSON_AddNumberToObject(_firewall_q, "usage", queue_cpy.firewall_queue_usage);

    cJSON *_fts_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "fts", _fts_q);

    cJSON_AddNumberToObject(_fts_q, "size", queue_cpy.fts_queue_size);
    cJSON_AddNumberToObject(_fts_q, "usage", queue_cpy.fts_queue_usage);

    cJSON *_hostinfo_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "hostinfo", _hostinfo_q);

    cJSON_AddNumberToObject(_hostinfo_q, "size", queue_cpy.hostinfo_queue_size);
    cJSON_AddNumberToObject(_hostinfo_q, "usage", queue_cpy.hostinfo_queue_usage);

    cJSON *_others_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "others", _others_q);

    cJSON_AddNumberToObject(_others_q, "size", queue_cpy.events_queue_size);
    cJSON_AddNumberToObject(_others_q, "usage", queue_cpy.events_queue_usage);

    cJSON *_processed_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "processed", _processed_q);

    cJSON_AddNumberToObject(_processed_q, "size", queue_cpy.processed_queue_size);
    cJSON_AddNumberToObject(_processed_q, "usage", queue_cpy.processed_queue_usage);

    cJSON *_rootcheck_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "rootcheck", _rootcheck_q);

    cJSON_AddNumberToObject(_rootcheck_q, "size", queue_cpy.rootcheck_queue_size);
    cJSON_AddNumberToObject(_rootcheck_q, "usage", queue_cpy.rootcheck_queue_usage);

    cJSON *_sca_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "sca", _sca_q);

    cJSON_AddNumberToObject(_sca_q, "size", queue_cpy.sca_queue_size);
    cJSON_AddNumberToObject(_sca_q, "usage", queue_cpy.sca_queue_usage);

    cJSON *_stats_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "stats", _stats_q);

    cJSON_AddNumberToObject(_stats_q, "size", queue_cpy.stats_queue_size);
    cJSON_AddNumberToObject(_stats_q, "usage", queue_cpy.stats_queue_usage);

    cJSON *_syscheck_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "syscheck", _syscheck_q);

    cJSON_AddNumberToObject(_syscheck_q, "size", queue_cpy.syscheck_queue_size);
    cJSON_AddNumberToObject(_syscheck_q, "usage", queue_cpy.syscheck_queue_usage);

    cJSON *_syscollector_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "syscollector", _syscollector_q);

    cJSON_AddNumberToObject(_syscollector_q, "size", queue_cpy.syscollector_queue_size);
    cJSON_AddNumberToObject(_syscollector_q, "usage", queue_cpy.syscollector_queue_usage);

    cJSON *_upgrade_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "upgrade", _upgrade_q);

    cJSON_AddNumberToObject(_upgrade_q, "size", queue_cpy.upgrade_queue_size);
    cJSON_AddNumberToObject(_upgrade_q, "usage", queue_cpy.upgrade_queue_usage);

    return asys_state_json;
}

cJSON* asys_create_agents_state_json(int* agents_ids) {
    analysisd_agent_state_t * agent_state;

    cJSON *asys_state_json = cJSON_CreateObject();
    cJSON *_array = cJSON_CreateArray();

    cJSON_AddNumberToObject(asys_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(asys_state_json, "name", ARGV0);

    w_mutex_lock(&agents_state_mutex);

    if (agents_ids != NULL) {
        for (int i = 0; agents_ids[i] != -1; i++) {
            char agent_id[OS_SIZE_16] = {0};
            snprintf(agent_id, OS_SIZE_16, "%.3d", agents_ids[i]);
            if (agent_state = (analysisd_agent_state_t *) OSHash_Get_ex(analysisd_agents_state, agent_id), agent_state != NULL) {
                cJSON *_item = cJSON_CreateObject();

                cJSON_AddNumberToObject(_item, "uptime", agent_state->uptime);
                cJSON_AddNumberToObject(_item, "id", agents_ids[i]);

                cJSON *_metrics = cJSON_CreateObject();
                cJSON_AddItemToObject(_item, "metrics", _metrics);

                // Fields within metrics are sorted alphabetically

                cJSON *_events = cJSON_CreateObject();
                cJSON_AddItemToObject(_metrics, "events", _events);

                cJSON_AddNumberToObject(_events, "processed", agent_state->events_processed);

                cJSON *_received_breakdown = cJSON_CreateObject();
                cJSON_AddItemToObject(_events, "received_breakdown", _received_breakdown);

                cJSON *_decoded_breakdown = cJSON_CreateObject();
                cJSON_AddItemToObject(_received_breakdown, "decoded_breakdown", _decoded_breakdown);

                cJSON_AddNumberToObject(_decoded_breakdown, "agent", agent_state->events_decoded_breakdown.agent);
                cJSON_AddNumberToObject(_decoded_breakdown, "dbsync", agent_state->events_decoded_breakdown.dbsync);

                cJSON *_decoded_integrations = cJSON_CreateObject();
                cJSON_AddItemToObject(_decoded_breakdown, "integrations_breakdown", _decoded_integrations);

                cJSON_AddNumberToObject(_decoded_integrations, "virustotal", agent_state->events_decoded_breakdown.integrations.virustotal);

                cJSON *_decoded_modules = cJSON_CreateObject();
                cJSON_AddItemToObject(_decoded_breakdown, "modules_breakdown", _decoded_modules);

                cJSON_AddNumberToObject(_decoded_modules, "aws", agent_state->events_decoded_breakdown.modules.aws);
                cJSON_AddNumberToObject(_decoded_modules, "azure", agent_state->events_decoded_breakdown.modules.azure);
                cJSON_AddNumberToObject(_decoded_modules, "ciscat", agent_state->events_decoded_breakdown.modules.ciscat);
                cJSON_AddNumberToObject(_decoded_modules, "command", agent_state->events_decoded_breakdown.modules.command);
                cJSON_AddNumberToObject(_decoded_modules, "docker", agent_state->events_decoded_breakdown.modules.docker);
                cJSON_AddNumberToObject(_decoded_modules, "gcp", agent_state->events_decoded_breakdown.modules.gcp);
                cJSON_AddNumberToObject(_decoded_modules, "github", agent_state->events_decoded_breakdown.modules.github);

                cJSON *_decoded_modules_logcollector = cJSON_CreateObject();
                cJSON_AddItemToObject(_decoded_modules, "logcollector_breakdown", _decoded_modules_logcollector);

                cJSON_AddNumberToObject(_decoded_modules_logcollector, "eventchannel", agent_state->events_decoded_breakdown.modules.logcollector.eventchannel);
                cJSON_AddNumberToObject(_decoded_modules_logcollector, "eventlog", agent_state->events_decoded_breakdown.modules.logcollector.eventlog);
                cJSON_AddNumberToObject(_decoded_modules_logcollector, "macos", agent_state->events_decoded_breakdown.modules.logcollector.macos);
                cJSON_AddNumberToObject(_decoded_modules_logcollector, "others", agent_state->events_decoded_breakdown.modules.logcollector.others);

                cJSON_AddNumberToObject(_decoded_modules, "office365", agent_state->events_decoded_breakdown.modules.office365);
                cJSON_AddNumberToObject(_decoded_modules, "ms-graph", agent_state->events_decoded_breakdown.modules.ms_graph);
                cJSON_AddNumberToObject(_decoded_modules, "oscap", agent_state->events_decoded_breakdown.modules.oscap);
                cJSON_AddNumberToObject(_decoded_modules, "osquery", agent_state->events_decoded_breakdown.modules.osquery);
                cJSON_AddNumberToObject(_decoded_modules, "rootcheck", agent_state->events_decoded_breakdown.modules.rootcheck);
                cJSON_AddNumberToObject(_decoded_modules, "sca", agent_state->events_decoded_breakdown.modules.sca);
                cJSON_AddNumberToObject(_decoded_modules, "syscheck", agent_state->events_decoded_breakdown.modules.syscheck);
                cJSON_AddNumberToObject(_decoded_modules, "syscollector", agent_state->events_decoded_breakdown.modules.syscollector);
                cJSON_AddNumberToObject(_decoded_modules, "upgrade", agent_state->events_decoded_breakdown.modules.upgrade);
                cJSON_AddNumberToObject(_decoded_modules, "vulnerability", agent_state->events_decoded_breakdown.modules.vulnerability);

                cJSON_AddNumberToObject(_decoded_breakdown, "monitor", agent_state->events_decoded_breakdown.monitor);
                cJSON_AddNumberToObject(_decoded_breakdown, "remote", agent_state->events_decoded_breakdown.remote);

                cJSON *_written_breakdown = cJSON_CreateObject();
                cJSON_AddItemToObject(_events, "written_breakdown", _written_breakdown);

                cJSON_AddNumberToObject(_written_breakdown, "alerts", agent_state->alerts_written);
                cJSON_AddNumberToObject(_written_breakdown, "archives", agent_state->archives_written);
                cJSON_AddNumberToObject(_written_breakdown, "firewall", agent_state->firewall_written);

                cJSON_AddItemToArray(_array, _item);
            }
        }
    }

    cJSON_AddItemToObject(asys_state_json, "agents", _array);
    w_mutex_unlock(&agents_state_mutex);

    return asys_state_json;
}
