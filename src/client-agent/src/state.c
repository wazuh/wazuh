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

#ifdef WIN32
#define localtime_r(x, y) localtime_s(y, x)
/* No portable gmtime_r on the mingw C runtime; same shim the other C callers
 * use (see syscheckd/src/file/events.c). */
#define gmtime_r(x, y) (gmtime_s(y, x) == 0 ? (y) : NULL)
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
        mdebug1("State file is disabled.");
#ifdef WIN32
        return 0;
#else
        return NULL;
#endif
    }

    mdebug1("Agent state cleanup thread started.");

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

    if (!strcmp(__local_name, "unset")) {
        merror("At write_state(): __local_name is unset.");
        return -1;
    }

    mdebug2("Updating state file.");

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
        "# Number of generated events\n"
        W_AGENTD_FIELD_MSG_COUNT "='%u'\n"
        "\n"
        "# Number of messages (events + control messages) sent to the manager\n"
        W_AGENTD_FIELD_MSG_SENT "='%u'\n"
        "\n"
        "# Number of events currently buffered\n"
        "# Always empty: the HTTPS accumulator reports occupancy as a ladder,\n"
        "# not as a count\n"
        , __local_name, agt->notify_time, agt->max_time_reconnect_try, status,
        last_keepalive, agent_state.msg_count, agent_state.msg_sent);

        fprintf(fp, W_AGENTD_FIELD_MSG_BUFF "=''\n");

    fprintf(fp,
        "\n"
        "# /control tasks routed to a handler\n"
        W_AGENTD_FIELD_TASK_DISPATCHED "='%u'\n"
        "\n"
        "# /control tasks discarded as duplicates (durable registry)\n"
        W_AGENTD_FIELD_TASK_DUPLICATE "='%u'\n"
        "\n"
        "# /control tasks that failed to dispatch/execute\n"
        W_AGENTD_FIELD_TASK_FAILED "='%u'\n",
        agent_state.task_dispatched, agent_state.task_discarded_duplicate,
        agent_state.task_failed);

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
    case INCREMENT_TASK_DISPATCHED:
        agent_state.task_dispatched++;
        break;
    case INCREMENT_TASK_DISCARDED_DUPLICATE:
        agent_state.task_discarded_duplicate++;
        break;
    case INCREMENT_TASK_FAILED:
        agent_state.task_failed++;
        break;
    default:
        break;
    }

    w_mutex_unlock(&state_mutex);
    return;
}

/* Each task counter is reported as {"total": n}: ".total" is the wcs marker for
 * a counter that is monotonic over the process's uptime. */
static void w_agentd_state_add_counter(cJSON * parent, const char * name, unsigned int value) {
    cJSON * counter = cJSON_CreateObject();

    if (!counter) {
        return;
    }

    cJSON_AddNumberToObject(counter, W_AGENTD_FIELD_TOTAL, value);
    cJSON_AddItemToObject(parent, name, counter);
}

cJSON * w_agentd_state_get(void) {

    char last_keepalive[W_AGENTD_STATE_TIME_ISO8601_LENGHT] = {0};
    struct tm tm = {.tm_sec = 0};

    cJSON * body = cJSON_CreateObject();
    cJSON * messages = cJSON_CreateObject();
    cJSON * tasks = cJSON_CreateObject();

    if (!body || !messages || !tasks) {
        cJSON_Delete(body);
        cJSON_Delete(messages);
        cJSON_Delete(tasks);
        return NULL;
    }

    w_mutex_lock(&state_mutex);
    const char * status = get_str_status(agent_state.status);

    /* gmtime_r, not localtime_r: only the agent knows its own offset, so a naive
     * local time cannot be resolved to an instant downstream. */
    if (agent_state.last_keepalive) {
        gmtime_r(&agent_state.last_keepalive, &tm);
        strftime(last_keepalive, sizeof(last_keepalive), W_AGENTD_STATE_TIME_FORMAT_ISO8601, &tm);
    }

    const unsigned int count = agent_state.msg_count;
    const unsigned int dispatched = agent_state.task_dispatched;
    const unsigned int duplicate = agent_state.task_discarded_duplicate;
    const unsigned int failed = agent_state.task_failed;
    w_mutex_unlock(&state_mutex);

    cJSON_AddStringToObject(body, W_AGENTD_FIELD_STATUS, status);

    /* Omitted rather than sent empty: the field is mapped `date`, and an empty
     * string is not a parsable one, so the indexer would reject the whole
     * document -- silently, since the push is fire-and-forget. */
    if (last_keepalive[0] != '\0') {
        cJSON_AddStringToObject(body, W_AGENTD_FIELD_KEEP_ALIVE, last_keepalive);
    }

    cJSON_AddNumberToObject(messages, W_AGENTD_FIELD_MESSAGES_COUNT, count);
    cJSON_AddItemToObject(body, W_AGENTD_FIELD_MESSAGES, messages);

    w_agentd_state_add_counter(tasks, W_AGENTD_FIELD_TASK_DISPATCHED, dispatched);
    w_agentd_state_add_counter(tasks, W_AGENTD_FIELD_TASK_DUPLICATE, duplicate);
    w_agentd_state_add_counter(tasks, W_AGENTD_FIELD_TASK_FAILED, failed);
    cJSON_AddItemToObject(body, W_AGENTD_FIELD_TASKS, tasks);

    return body;
}
