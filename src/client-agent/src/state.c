/* Agent state management functions
 * August 2, 2017
 *
 * Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <pthread.h>
#include "state.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

agent_state_t agent_state = { .status = GA_STATUS_PENDING };
static pthread_mutex_t state_mutex;

static int write_state();
STATIC const char * get_str_status(agent_status_t status);

int interval;

void w_agentd_state_init() {
    w_mutex_init(&state_mutex, NULL);
    interval = getDefine_Int("agent", "state_interval", 0, 86400);
}

#ifdef WIN32
DWORD WINAPI state_main(__attribute__((unused)) LPVOID arg) {
#else
void * state_main(__attribute__((unused)) void * args) {
#endif
    if (!interval) {
        minfo("State file is disabled.");
#ifdef WIN32
        return 0;
#else
        return NULL;
#endif
    }

    mdebug1("State file updating thread started.");

    while (1) {
        write_state();
        sleep(interval);
    }

#ifdef WIN32
        return 0;
#else
        return NULL;
#endif
}

int write_state() {
    FILE * fp;
    struct tm tm = { .tm_sec = 0 };
    const char * status;
    char path[PATH_MAX - 8];
    char last_keepalive[1024] = "";
    char last_ack[1024] = "";
    int buffered_event;

    if (!strcmp(__local_name, "unset")) {
        merror("At write_state(): __local_name is unset.");
        return -1;
    }

    mdebug2("Updating state file.");

    buffered_event = w_agentd_get_buffer_lenght();
    w_mutex_lock(&state_mutex);

#ifdef WIN32
    snprintf(path, sizeof(path), "%s.state", __local_name);

    if (fp = wfopen(path, "w"), !fp) {
        merror(FOPEN_ERROR, path, errno, strerror(errno));
        w_mutex_unlock(&state_mutex);
        return -1;
    }
#else
    char path_temp[PATH_MAX + 1];
    snprintf(path, sizeof(path), OS_PIDFILE "/%s.state", __local_name);
    snprintf(path_temp, sizeof(path_temp), "%s.temp", path);

    if (fp = wfopen(path_temp, "w"), !fp) {
        merror(FOPEN_ERROR, path_temp, errno, strerror(errno));
        w_mutex_unlock(&state_mutex);
        return -1;
    }
#endif

    status = get_str_status(agent_state.status);

    if (agent_state.last_keepalive) {
        localtime_r(&agent_state.last_keepalive, &tm);
        strftime(last_keepalive, sizeof(last_keepalive), W_AGENTD_STATE_TIME_FORMAT, &tm);
    }

    if (agent_state.last_ack) {
        localtime_r(&agent_state.last_ack, &tm);
        strftime(last_ack, sizeof(last_ack), W_AGENTD_STATE_TIME_FORMAT, &tm);
    }

    fprintf(fp,
        "# State file for %s\n"
        "\n"
        "# Agent status:\n"
        "# - pending:      waiting to get connected.\n"
        "# - connected:    connection established with manager in the last %d seconds.\n"
        "# - disconnected: connection lost or no ACK received in the last %d seconds.\n"
        W_AGENTD_FIELD_STATUS "='%s'\n"
        "\n"
        "# Last time a keepalive was sent\n"
        W_AGENTD_FIELD_KEEP_ALIVE "='%s'\n"
        "\n"
        "# Last time a control message was received\n"
        W_AGENTD_FIELD_LAST_ACK "='%s'\n"
        "\n"
        "# Number of generated events\n"
        W_AGENTD_FIELD_MSG_COUNT "='%u'\n"
        "\n"
        "# Number of messages (events + control messages) sent to the manager\n"
        W_AGENTD_FIELD_MSG_SENT "='%u'\n"
        "\n"
        "# Number of events currently buffered\n"
        "# Empty if anti-flooding mechanism is disabled\n"
        , __local_name, agt->notify_time, agt->max_time_reconnect_try, status,
        last_keepalive, last_ack, agent_state.msg_count, agent_state.msg_sent);

        if (buffered_event >= 0) {
            fprintf(fp, W_AGENTD_FIELD_MSG_BUFF "='%i'\n", buffered_event);
        } else {
            fprintf(fp, W_AGENTD_FIELD_MSG_BUFF "=''\n");
        }

    fclose(fp);

#ifndef WIN32
    if (rename(path_temp, path) < 0) {
        merror("Renaming %s to %s: %s", path_temp, path, strerror(errno));

        if (unlink(path_temp) < 0) {
            merror("Deleting %s: %s", path_temp, strerror(errno));
        }

        w_mutex_unlock(&state_mutex);
        return -1;
    }
#endif

    w_mutex_unlock(&state_mutex);
    return 0;
}

STATIC const char * get_str_status(agent_status_t status) {

    const char * retval = NULL;

    switch (status) {
    case GA_STATUS_PENDING:
        retval = "pending";
        break;
    case GA_STATUS_ACTIVE:
        retval = "connected";
        break;
    case GA_STATUS_NACTIVE:
        retval = "disconnected";
        break;
    default:
        merror("At get_str_status(): Unknown status (%d)", status);
        retval = "unknown";
    }

    return retval;
}

void w_agentd_state_update(w_agentd_state_update_t type, void * data) {

    w_mutex_lock(&state_mutex);

    switch (type) {
    case UPDATE_STATUS:
        agent_state.status = (agent_status_t) data;
        break;
    case UPDATE_KEEPALIVE:
        if (data != NULL) {
            agent_state.last_keepalive = *((time_t *) data);
        }
        break;
    case UPDATE_ACK:
        if (data != NULL) {
            agent_state.last_ack = *((time_t *) data);
        }
        break;
    case INCREMENT_MSG_COUNT:
        agent_state.msg_count++;
        break;
    case INCREMENT_MSG_SEND:
        agent_state.msg_sent++;
        break;
    case RESET_MSG_COUNT_ON_SHRINK:
        if (data != NULL) {
            agent_state.msg_count = *((unsigned int *) data);
        }
        break;
    default:
        break;
    }

    w_mutex_unlock(&state_mutex);
    return;
}

char * w_agentd_state_get() {

    const char * status = NULL;
    char last_keepalive[W_AGENTD_STATE_TIME_LENGHT] = {0};
    char last_ack[W_AGENTD_STATE_TIME_LENGHT] = {0};
    unsigned int count;
    unsigned int sent;
    int buffered_event;
    bool buffer_enable = true;

    struct tm tm = {.tm_sec = 0};
    char * retval = NULL;
    cJSON * json_retval = cJSON_CreateObject();
    cJSON * data = cJSON_CreateObject();

    /* Get status info */
    w_mutex_lock(&state_mutex);
    status = get_str_status(agent_state.status);

    if (agent_state.last_keepalive) {
        localtime_r(&agent_state.last_keepalive, &tm);
        strftime(last_keepalive, sizeof(last_keepalive), W_AGENTD_STATE_TIME_FORMAT, &tm);
    }

    if (agent_state.last_ack) {
        localtime_r(&agent_state.last_ack, &tm);
        strftime(last_ack, sizeof(last_ack), W_AGENTD_STATE_TIME_FORMAT, &tm);
    }

    count = agent_state.msg_count;
    sent = agent_state.msg_sent;
    w_mutex_unlock(&state_mutex);

    if (buffered_event = w_agentd_get_buffer_lenght(), buffered_event < 0) {
        buffer_enable = false;
        buffered_event = 0;
    }

    /* json response */
    cJSON_AddNumberToObject(json_retval, W_AGENTD_JSON_ERROR, 0);
    cJSON_AddItemToObject(json_retval, W_AGENTD_JSON_DATA, data);

    cJSON_AddStringToObject(data, W_AGENTD_FIELD_STATUS, status);
    cJSON_AddStringToObject(data, W_AGENTD_FIELD_KEEP_ALIVE, last_keepalive);
    cJSON_AddStringToObject(data, W_AGENTD_FIELD_LAST_ACK, last_ack);
    cJSON_AddNumberToObject(data, W_AGENTD_FIELD_MSG_COUNT, count);
    cJSON_AddNumberToObject(data, W_AGENTD_FIELD_MSG_SENT, sent);
    cJSON_AddNumberToObject(data, W_AGENTD_FIELD_MSG_BUFF, buffered_event);
    cJSON_AddBoolToObject(data, W_AGENTD_FIELD_EN_BUFF, buffer_enable);

    retval = cJSON_PrintUnformatted(json_retval);
    cJSON_Delete(json_retval);

    return retval;
}
