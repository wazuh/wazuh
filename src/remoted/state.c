/* Remoted state management functions
 * May 25, 2018
 *
 * Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "remoted.h"
#include "state.h"
#include <pthread.h>
#include "wazuh_db/helpers/wdb_global_helpers.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

remoted_state_t remoted_state;
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t agents_state_mutex = PTHREAD_MUTEX_INITIALIZER;
static int rem_write_state();
static char *refresh_time;

extern OSHash *remoted_agents_state;

/**
 * @brief Search or create and return agent state node
 * @param agent_id Id of the agent that corresponds to the node
 * @return remoted_agent_state_t node
 */
STATIC remoted_agent_state_t * get_node(const char *agent_id);

/**
 * @brief Clean non active agents from agents state.
 */
STATIC void w_remoted_clean_agents_state();

/**
 * @brief Increment received event messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_recv_evt(const char *agent_id);

/**
 * @brief Increment received control messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_recv_ctrl(const char *agent_id);

/**
 * @brief Increment received keepalive control messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_recv_ctrl_keepalive(const char *agent_id);

/**
 * @brief Increment received startup control messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_recv_ctrl_startup(const char *agent_id);

/**
 * @brief Increment received shutdown control messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_recv_ctrl_shutdown(const char *agent_id);

/**
 * @brief Increment received request control messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_recv_ctrl_request(const char *agent_id);

/**
 * @brief Increment sent ack messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_send_ack(const char *agent_id);

/**
 * @brief Increment sent shared file messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_send_shared(const char *agent_id);

/**
 * @brief Increment sent AR messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_send_ar(const char *agent_id);

/**
 * @brief Increment sent CFGA messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_send_cfga(const char *agent_id);

/**
 * @brief Increment sent request messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_send_request(const char *agent_id);

/**
 * @brief Increment sent discarded messages counter for agents
 * @param agent_id Id of the agent that corresponds to the message
 */
static void rem_inc_agents_send_discarded(const char *agent_id);

void * rem_state_main() {
    int interval = getDefine_Int("remoted", "state_interval", 0, 86400);

    if (!interval) {
        minfo("State file is disabled.");
        return NULL;
    }

    os_calloc(48, sizeof(char), refresh_time);
    if (interval < 60) {
        snprintf(refresh_time, 48, "Updated every %i seconds.", interval);
    } else if (interval < 3600) {
        snprintf(refresh_time, 48, "Updated every %i minutes.", interval/60);
    } else {
        snprintf(refresh_time, 48, "Updated every %i hours.", interval/3600);
    }

    mdebug1("State file updating thread started.");

    while (1) {
        rem_write_state();
        sleep(interval);
        w_remoted_clean_agents_state();
    }

    return NULL;
}

int rem_write_state() {
    FILE * fp;
    char path[PATH_MAX - 8];
    char path_temp[PATH_MAX + 1];
    remoted_state_t state_cpy;

    if (!strcmp(__local_name, "unset")) {
        merror("At write_state(): __local_name is unset.");
        return -1;
    }

    mdebug2("Updating state file.");

    snprintf(path, sizeof(path), OS_PIDFILE "/%s.state", __local_name);
    snprintf(path_temp, sizeof(path_temp), "%s.temp", path);

    if (fp = fopen(path_temp, "w"), !fp) {
        merror(FOPEN_ERROR, path_temp, errno, strerror(errno));
        return -1;
    }

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &remoted_state, sizeof(remoted_state_t));
    w_mutex_unlock(&state_mutex);

    fprintf(fp,
        "# State file for %s\n"
        "# THIS FILE WILL BE DEPRECATED IN FUTURE VERSIONS\n"
        "# %s\n"
        "\n"
        "# Queue size\n"
        "queue_size='%zu'\n"
        "\n"
        "# Total queue size\n"
        "total_queue_size='%zu'\n"
        "\n"
        "# TCP sessions\n"
        "tcp_sessions='%u'\n"
        "\n"
        "# Events sent to Analysisd\n"
        "evt_count='%lu'\n"
        "\n"
        "# Control messages received\n"
        "ctrl_msg_count='%lu'\n"
        "\n"
        "# Discarded messages\n"
        "discarded_count='%u'\n"
        "\n"
        "# Total number of bytes sent\n"
        "sent_bytes='%lu'\n"
        "\n"
        "# Total number of bytes received\n"
        "recv_bytes='%lu'\n"
        "\n"
        "# Messages dequeued after the agent closes the connection\n"
        "dequeued_after_close='%u'\n",
        __local_name, refresh_time, rem_get_qsize(), rem_get_tsize(), state_cpy.tcp_sessions,
        state_cpy.recv_breakdown.evt_count, state_cpy.recv_breakdown.ctrl_count, state_cpy.recv_breakdown.discarded_count,
        state_cpy.sent_bytes, state_cpy.recv_bytes, state_cpy.recv_breakdown.dequeued_count);

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

STATIC remoted_agent_state_t * get_node(const char *agent_id) {
    remoted_agent_state_t * agent_state = (remoted_agent_state_t *) OSHash_Get_ex(remoted_agents_state, agent_id);

    if(agent_state != NULL) {
        return agent_state;
    } else {
        os_calloc(1, sizeof(remoted_agent_state_t), agent_state);
        OSHash_Add_ex(remoted_agents_state, agent_id, agent_state);
        return agent_state;
    }
}

STATIC void w_remoted_clean_agents_state() {
    char *node_name = NULL;
    int *active_agents = NULL;
    int sock = -1;
    OSHashNode *hash_node;
    unsigned int inode_it = 0;

    hash_node = OSHash_Begin(remoted_agents_state, &inode_it);

    if (hash_node == NULL) {
        return;
    }

    node_name = get_node_name();
    active_agents = wdb_get_agents_by_connection_status(AGENT_CS_ACTIVE, &sock, node_name);
    os_free(node_name);
    if(!active_agents) {
        merror("Unable to get connected agents.");
        return;
    }

    char *agent_id = NULL;
    remoted_agent_state_t * agent_state = NULL;

    while (hash_node) {
        agent_id = hash_node->key;
        agent_state = hash_node->data;

        hash_node = OSHash_Next(remoted_agents_state, &inode_it, hash_node);

        int exist = 0;
        for (size_t i = 0; active_agents[i] != -1; i++) {
            if (atoi(agent_id) == active_agents[i] ) {
                exist = 1;
                break;
            }
        }

        if (exist == 0) {
            agent_state = (remoted_agent_state_t *)OSHash_Delete_ex(remoted_agents_state, agent_id);
            os_free(agent_state);
        }
    }

    return;
}

static void rem_inc_agents_recv_evt(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->recv_evt_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_recv_ctrl(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->recv_ctrl_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_recv_ctrl_keepalive(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->ctrl_breakdown.keepalive_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_recv_ctrl_startup(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->ctrl_breakdown.startup_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_recv_ctrl_shutdown(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->ctrl_breakdown.shutdown_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_recv_ctrl_request(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->ctrl_breakdown.request_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_send_ack(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->sent_breakdown.ack_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_send_shared(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->sent_breakdown.shared_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_send_ar(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->sent_breakdown.ar_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_send_cfga(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->sent_breakdown.cfga_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_send_request(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->sent_breakdown.request_count++;
    w_mutex_unlock(&agents_state_mutex);
}

static void rem_inc_agents_send_discarded(const char *agent_id) {
    w_mutex_lock(&agents_state_mutex);
    remoted_agent_state_t *agent_node = get_node(agent_id);
    agent_node->sent_breakdown.discarded_count++;
    w_mutex_unlock(&agents_state_mutex);
}

void rem_inc_tcp() {
    w_mutex_lock(&state_mutex);
    remoted_state.tcp_sessions++;
    w_mutex_unlock(&state_mutex);
}

void rem_dec_tcp() {
    w_mutex_lock(&state_mutex);
    remoted_state.tcp_sessions--;
    w_mutex_unlock(&state_mutex);
}

void rem_add_recv(unsigned long bytes) {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_bytes += bytes;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_evt(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.evt_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_recv_evt(agent_id);
    }
}

void rem_inc_recv_ctrl(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_recv_ctrl(agent_id);
    }
}

void rem_inc_recv_ping() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ping_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_unknown() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.unknown_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_dequeued() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.dequeued_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_discarded() {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.discarded_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_recv_ctrl_keepalive(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_breakdown.keepalive_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_recv_ctrl_keepalive(agent_id);
    }
}

void rem_inc_recv_ctrl_startup(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_breakdown.startup_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_recv_ctrl_startup(agent_id);
    }
}

void rem_inc_recv_ctrl_shutdown(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_breakdown.shutdown_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_recv_ctrl_shutdown(agent_id);
    }
}

void rem_inc_recv_ctrl_request(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.recv_breakdown.ctrl_breakdown.request_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_recv_ctrl_request(agent_id);
    }
}

void rem_add_send(unsigned long bytes) {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_bytes += bytes;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_send_ack(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.ack_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_send_ack(agent_id);
    }
}

void rem_inc_send_shared(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.shared_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_send_shared(agent_id);
    }
}

void rem_inc_send_ar(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.ar_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_send_ar(agent_id);
    }
}

void rem_inc_send_cfga(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.cfga_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_send_cfga(agent_id);
    }
}

void rem_inc_send_request(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.request_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_send_request(agent_id);
    }
}

void rem_inc_send_discarded(const char *agent_id) {
    w_mutex_lock(&state_mutex);
    remoted_state.sent_breakdown.discarded_count++;
    w_mutex_unlock(&state_mutex);

    if (agent_id != NULL) {
        rem_inc_agents_send_discarded(agent_id);
    }
}

void rem_inc_keys_reload() {
    w_mutex_lock(&state_mutex);
    remoted_state.keys_reload_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_update_shared_files() {
    w_mutex_lock(&state_mutex);
    remoted_state.update_shared_files_count++;
    w_mutex_unlock(&state_mutex);
}

cJSON* rem_create_state_json() {
    remoted_state_t state_cpy;
    cJSON *_statistics = NULL;
    cJSON *_received = NULL;
    cJSON *_control = NULL;
    cJSON *_sent = NULL;
    cJSON *_queue = NULL;

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &remoted_state, sizeof(remoted_state_t));
    w_mutex_unlock(&state_mutex);

    cJSON *rem_state_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(rem_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(rem_state_json, "name", ARGV0);

    _statistics = cJSON_CreateObject();
    cJSON_AddItemToObject(rem_state_json, "statistics", _statistics);

    cJSON_AddNumberToObject(_statistics, "tcp_sessions", state_cpy.tcp_sessions);

    cJSON_AddNumberToObject(_statistics, "received_bytes", state_cpy.recv_bytes);

    _received = cJSON_CreateObject();
    cJSON_AddItemToObject(_statistics, "messages_received_breakdown", _received);

    cJSON_AddNumberToObject(_received, "event_messages", state_cpy.recv_breakdown.evt_count);
    cJSON_AddNumberToObject(_received, "control_messages", state_cpy.recv_breakdown.ctrl_count);

    _control = cJSON_CreateObject();
    cJSON_AddItemToObject(_received, "control_breakdown", _control);

    cJSON_AddNumberToObject(_control, "request_messages", state_cpy.recv_breakdown.ctrl_breakdown.request_count);
    cJSON_AddNumberToObject(_control, "startup_messages", state_cpy.recv_breakdown.ctrl_breakdown.startup_count);
    cJSON_AddNumberToObject(_control, "shutdown_messages", state_cpy.recv_breakdown.ctrl_breakdown.shutdown_count);
    cJSON_AddNumberToObject(_control, "keepalive_messages", state_cpy.recv_breakdown.ctrl_breakdown.keepalive_count);

    cJSON_AddNumberToObject(_received, "ping_messages", state_cpy.recv_breakdown.ping_count);
    cJSON_AddNumberToObject(_received, "unknown_messages", state_cpy.recv_breakdown.unknown_count);
    cJSON_AddNumberToObject(_received, "dequeued_after_close_messages", state_cpy.recv_breakdown.dequeued_count);
    cJSON_AddNumberToObject(_received, "discarded_messages", state_cpy.recv_breakdown.discarded_count);

    cJSON_AddNumberToObject(_statistics, "sent_bytes", state_cpy.sent_bytes);

    _sent = cJSON_CreateObject();
    cJSON_AddItemToObject(_statistics, "messages_sent_breakdown", _sent);

    cJSON_AddNumberToObject(_sent, "ack_messages", state_cpy.sent_breakdown.ack_count);
    cJSON_AddNumberToObject(_sent, "shared_file_messages", state_cpy.sent_breakdown.shared_count);
    cJSON_AddNumberToObject(_sent, "ar_messages", state_cpy.sent_breakdown.ar_count);
    cJSON_AddNumberToObject(_sent, "cfga_messages", state_cpy.sent_breakdown.cfga_count);
    cJSON_AddNumberToObject(_sent, "request_messages", state_cpy.sent_breakdown.request_count);
    cJSON_AddNumberToObject(_sent, "discarded_messages", state_cpy.sent_breakdown.discarded_count);

    _queue = cJSON_CreateObject();
    cJSON_AddItemToObject(_statistics, "queue_status", _queue);

    cJSON_AddNumberToObject(_queue, "receive_queue_usage", rem_get_qsize());
    cJSON_AddNumberToObject(_queue, "receive_queue_size", rem_get_tsize());

    cJSON_AddNumberToObject(_statistics, "keys_reload_count", state_cpy.keys_reload_count);
    cJSON_AddNumberToObject(_statistics, "update_shared_files_count", state_cpy.update_shared_files_count);

    OSHashNode *hash_node;
    unsigned int index = 0;

    w_mutex_lock(&agents_state_mutex);

    if (hash_node = OSHash_Begin(remoted_agents_state, &index), hash_node != NULL) {
        remoted_agent_state_t * data = NULL;
        cJSON * _array = NULL;
        cJSON * _item = NULL;
        cJSON * _statistics = NULL;
        cJSON * _messages_received_breakdown = NULL;
        cJSON * _messages_sent_breakdown = NULL;
        cJSON * _control_breakdown = NULL;

        _array = cJSON_CreateArray();

        while (hash_node != NULL) {
            data = hash_node->data;

            _item = cJSON_CreateObject();
            _statistics = cJSON_CreateObject();
            _messages_received_breakdown = cJSON_CreateObject();
            _messages_sent_breakdown = cJSON_CreateObject();
            _control_breakdown = cJSON_CreateObject();

            cJSON_AddNumberToObject(_item, "agent_id", atoi(hash_node->key));
            cJSON_AddItemToObject(_item, "statistics", _statistics);

            cJSON_AddItemToObject(_statistics, "messages_received_breakdown", _messages_received_breakdown);

            cJSON_AddNumberToObject(_messages_received_breakdown, "event_messages", data->recv_evt_count);
            cJSON_AddNumberToObject(_messages_received_breakdown, "control_messages", data->recv_ctrl_count);

            cJSON_AddItemToObject(_messages_received_breakdown, "control_breakdown", _control_breakdown);

            cJSON_AddNumberToObject(_control_breakdown, "request_messages", data->ctrl_breakdown.request_count);
            cJSON_AddNumberToObject(_control_breakdown, "startup_messages", data->ctrl_breakdown.startup_count);
            cJSON_AddNumberToObject(_control_breakdown, "shutdown_messages", data->ctrl_breakdown.shutdown_count);
            cJSON_AddNumberToObject(_control_breakdown, "keepalive_messages", data->ctrl_breakdown.keepalive_count);

            cJSON_AddItemToObject(_statistics, "messages_sent_breakdown", _messages_sent_breakdown);

            cJSON_AddNumberToObject(_messages_sent_breakdown, "ack_messages", data->sent_breakdown.ack_count);
            cJSON_AddNumberToObject(_messages_sent_breakdown, "shared_file_messages", data->sent_breakdown.shared_count);
            cJSON_AddNumberToObject(_messages_sent_breakdown, "ar_messages", data->sent_breakdown.ar_count);
            cJSON_AddNumberToObject(_messages_sent_breakdown, "cfga_messages", data->sent_breakdown.cfga_count);
            cJSON_AddNumberToObject(_messages_sent_breakdown, "request_messages", data->sent_breakdown.request_count);
            cJSON_AddNumberToObject(_messages_sent_breakdown, "discarded_messages", data->sent_breakdown.discarded_count);

            cJSON_AddItemToArray(_array, _item);

            hash_node = OSHash_Next(remoted_agents_state, &index, hash_node);
        }

        cJSON_AddItemToObject(rem_state_json, "agents_connected", _array);
    }
    w_mutex_unlock(&agents_state_mutex);

    return rem_state_json;
}
