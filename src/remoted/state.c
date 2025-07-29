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

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

remoted_state_t remoted_state = {0};
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
 * @brief Clean non active agents from agents state
 * @param sock Wazuh DB socket
 */
STATIC void w_remoted_clean_agents_state(int *sock);

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

    int sock = -1;
    sock = wdbc_connect();

    while (1) {
        rem_write_state();
        sleep(interval);
        w_remoted_clean_agents_state(&sock);
    }

    wdbc_close(&sock);

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

    if (fp = wfopen(path_temp, "w"), !fp) {
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
        "# Events sent to Engine\n"
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
        "dequeued_after_close='%u'\n"
        "# Control messages queue usage\n"
        "ctrl_msg_queue_usage='%u'\n"
        "\n",
        __local_name, refresh_time, rem_get_qsize(), rem_get_tsize(), state_cpy.tcp_sessions,
        state_cpy.recv_breakdown.evt_count, state_cpy.recv_breakdown.ctrl_count, state_cpy.recv_breakdown.discarded_count,
        state_cpy.sent_bytes, state_cpy.recv_bytes, state_cpy.recv_breakdown.dequeued_count,
        state_cpy.ctrl_msg_queue_usage);

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
        agent_state->uptime = time(NULL);
        OSHash_Add_ex(remoted_agents_state, agent_id, agent_state);
        return agent_state;
    }
}

STATIC void w_remoted_clean_agents_state(int *sock) {
    int *active_agents = NULL;
    OSHashNode *hash_node;
    unsigned int inode_it = 0;

    hash_node = OSHash_Begin_ex(remoted_agents_state, &inode_it);

    if (hash_node == NULL) {
        return;
    }

    if (active_agents = wdb_get_agents_ids_of_current_node(AGENT_CS_ACTIVE, sock, 0, -1), active_agents == NULL) {
        return;
    }

    char *agent_id = NULL;
    remoted_agent_state_t * agent_state = NULL;

    while (hash_node) {
        agent_id = hash_node->key;

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

    os_free(active_agents);
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
    agent_node->sent_breakdown.sca_count++;
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

void rem_inc_ctrl_msg_queue_usage() {
    w_mutex_lock(&state_mutex);
    remoted_state.ctrl_msg_queue_usage++;
    w_mutex_unlock(&state_mutex);
}

void rem_dec_ctrl_msg_queue_usage() {
    w_mutex_lock(&state_mutex);
    remoted_state.ctrl_msg_queue_usage--;
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
    remoted_state.sent_breakdown.sca_count++;
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

cJSON* rem_create_state_json() {
    remoted_state_t state_cpy;

    w_mutex_lock(&state_mutex);
    memcpy(&state_cpy, &remoted_state, sizeof(remoted_state_t));
    w_mutex_unlock(&state_mutex);

    cJSON *rem_state_json = cJSON_CreateObject();

    cJSON_AddNumberToObject(rem_state_json, "uptime", state_cpy.uptime);
    cJSON_AddNumberToObject(rem_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(rem_state_json, "name", ARGV0);

    cJSON *_metrics = cJSON_CreateObject();
    cJSON_AddItemToObject(rem_state_json, "metrics", _metrics);

    // Fields within metrics are sorted alphabetically

    cJSON *_bytes = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "bytes", _bytes);

    cJSON_AddNumberToObject(_bytes, "received", state_cpy.recv_bytes);
    cJSON_AddNumberToObject(_bytes, "sent", state_cpy.sent_bytes);

    cJSON_AddNumberToObject(_metrics, "keys_reload_count", state_cpy.keys_reload_count);

    cJSON *_messages = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "messages", _messages);

    cJSON *_received_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_messages, "received_breakdown", _received_breakdown);

    cJSON_AddNumberToObject(_received_breakdown, "control", state_cpy.recv_breakdown.ctrl_count);

    cJSON *_control_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_received_breakdown, "control_breakdown", _control_breakdown);

    cJSON_AddNumberToObject(_control_breakdown, "keepalive", state_cpy.recv_breakdown.ctrl_breakdown.keepalive_count);
    cJSON_AddNumberToObject(_control_breakdown, "request", state_cpy.recv_breakdown.ctrl_breakdown.request_count);
    cJSON_AddNumberToObject(_control_breakdown, "shutdown", state_cpy.recv_breakdown.ctrl_breakdown.shutdown_count);
    cJSON_AddNumberToObject(_control_breakdown, "startup", state_cpy.recv_breakdown.ctrl_breakdown.startup_count);

    cJSON_AddNumberToObject(_received_breakdown, "dequeued_after", state_cpy.recv_breakdown.dequeued_count);
    cJSON_AddNumberToObject(_received_breakdown, "discarded", state_cpy.recv_breakdown.discarded_count);
    cJSON_AddNumberToObject(_received_breakdown, "event", state_cpy.recv_breakdown.evt_count);
    cJSON_AddNumberToObject(_received_breakdown, "ping", state_cpy.recv_breakdown.ping_count);
    cJSON_AddNumberToObject(_received_breakdown, "unknown", state_cpy.recv_breakdown.unknown_count);

    cJSON *_sent_breakdown = cJSON_CreateObject();
    cJSON_AddItemToObject(_messages, "sent_breakdown", _sent_breakdown);

    cJSON_AddNumberToObject(_sent_breakdown, "ack", state_cpy.sent_breakdown.ack_count);
    cJSON_AddNumberToObject(_sent_breakdown, "ar", state_cpy.sent_breakdown.ar_count);
    cJSON_AddNumberToObject(_sent_breakdown, "discarded", state_cpy.sent_breakdown.discarded_count);
    cJSON_AddNumberToObject(_sent_breakdown, "request", state_cpy.sent_breakdown.request_count);
    cJSON_AddNumberToObject(_sent_breakdown, "sca", state_cpy.sent_breakdown.sca_count);
    cJSON_AddNumberToObject(_sent_breakdown, "shared", state_cpy.sent_breakdown.shared_count);

    cJSON *_queues = cJSON_CreateObject();
    cJSON_AddItemToObject(_metrics, "queues", _queues);

    cJSON *_received_q = cJSON_CreateObject();
    cJSON_AddItemToObject(_queues, "received", _received_q);

    cJSON_AddNumberToObject(_received_q, "size", rem_get_tsize());
    cJSON_AddNumberToObject(_received_q, "usage", rem_get_qsize());

    cJSON_AddNumberToObject(_metrics, "tcp_sessions", state_cpy.tcp_sessions);

    cJSON_AddNumberToObject(_metrics, "control_messages_queue_usage", state_cpy.ctrl_msg_queue_usage);

    return rem_state_json;
}

cJSON* rem_create_agents_state_json(int* agents_ids) {
    remoted_agent_state_t * agent_state;

    cJSON *rem_state_json = cJSON_CreateObject();
    cJSON *_array = cJSON_CreateArray();

    cJSON_AddNumberToObject(rem_state_json, "timestamp", time(NULL));
    cJSON_AddStringToObject(rem_state_json, "name", ARGV0);

    w_mutex_lock(&agents_state_mutex);

    if (agents_ids != NULL) {
        for (int i = 0; agents_ids[i] != -1; i++) {
            char agent_id[OS_SIZE_16] = {0};
            snprintf(agent_id, OS_SIZE_16, "%.3d", agents_ids[i]);
            if (agent_state = (remoted_agent_state_t *) OSHash_Get_ex(remoted_agents_state, agent_id), agent_state != NULL) {
                cJSON *_item = cJSON_CreateObject();

                cJSON_AddNumberToObject(_item, "uptime", agent_state->uptime);
                cJSON_AddNumberToObject(_item, "id", agents_ids[i]);

                cJSON *_metrics = cJSON_CreateObject();
                cJSON_AddItemToObject(_item, "metrics", _metrics);

                // Fields within metrics are sorted alphabetically

                cJSON *_messages = cJSON_CreateObject();
                cJSON_AddItemToObject(_metrics, "messages", _messages);

                cJSON *_received_breakdown = cJSON_CreateObject();
                cJSON_AddItemToObject(_messages, "received_breakdown", _received_breakdown);

                cJSON_AddNumberToObject(_received_breakdown, "control", agent_state->recv_ctrl_count);

                cJSON *_control_breakdown = cJSON_CreateObject();
                cJSON_AddItemToObject(_received_breakdown, "control_breakdown", _control_breakdown);

                cJSON_AddNumberToObject(_control_breakdown, "keepalive", agent_state->ctrl_breakdown.keepalive_count);
                cJSON_AddNumberToObject(_control_breakdown, "request", agent_state->ctrl_breakdown.request_count);
                cJSON_AddNumberToObject(_control_breakdown, "shutdown", agent_state->ctrl_breakdown.shutdown_count);
                cJSON_AddNumberToObject(_control_breakdown, "startup", agent_state->ctrl_breakdown.startup_count);

                cJSON_AddNumberToObject(_received_breakdown, "event", agent_state->recv_evt_count);

                cJSON *_sent_breakdown = cJSON_CreateObject();
                cJSON_AddItemToObject(_messages, "sent_breakdown", _sent_breakdown);

                cJSON_AddNumberToObject(_sent_breakdown, "ack", agent_state->sent_breakdown.ack_count);
                cJSON_AddNumberToObject(_sent_breakdown, "ar", agent_state->sent_breakdown.ar_count);
                cJSON_AddNumberToObject(_sent_breakdown, "discarded", agent_state->sent_breakdown.discarded_count);
                cJSON_AddNumberToObject(_sent_breakdown, "request", agent_state->sent_breakdown.request_count);
                cJSON_AddNumberToObject(_sent_breakdown, "sca", agent_state->sent_breakdown.sca_count);
                cJSON_AddNumberToObject(_sent_breakdown, "shared", agent_state->sent_breakdown.shared_count);

                cJSON_AddItemToArray(_array, _item);
            }
        }
    }

    cJSON_AddItemToObject(rem_state_json, "agents", _array);
    w_mutex_unlock(&agents_state_mutex);

    return rem_state_json;
}
