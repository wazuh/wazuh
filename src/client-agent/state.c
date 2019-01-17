/* Agent state management functions
 * August 2, 2017
 *
 * Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "agentd.h"
#include <pthread.h>

agent_state_t agent_state = { .status = GA_STATUS_PENDING };
pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;

static int write_state();

int interval;

void * state_main(__attribute__((unused)) void * args) {
    interval = getDefine_Int("agent", "state_interval", 0, 86400);

    if (!interval) {
        minfo("State file is disabled.");
        return NULL;
    }

    mdebug1("State file updating thread started.");

    while (1) {
        write_state();
        sleep(interval);
    }

    return NULL;
}

void update_status(agent_status_t status) {
    agent_state.status = status;
}

void update_keepalive(time_t curr_time) {
    agent_state.last_keepalive = curr_time;
}

void update_ack(time_t curr_time) {
    agent_state.last_ack = curr_time;
}

int write_state() {
    FILE * fp;
    struct tm tm;
    const char * status;
    char path[PATH_MAX + 1];
    char last_keepalive[1024] = "";
    char last_ack[1024] = "";

    if (!strcmp(__local_name, "unset")) {
        merror("At write_state(): __local_name is unset.");
        return -1;
    }

    mdebug2("Updating state file.");
    w_mutex_lock(&state_mutex);

#ifdef WIN32
    snprintf(path, sizeof(path), "%s.state", __local_name);

    if (fp = fopen(path, "w"), !fp) {
        merror(FOPEN_ERROR, path, errno, strerror(errno));
        w_mutex_unlock(&state_mutex);
        return -1;
    }
#else
    char path_temp[PATH_MAX + 1];
    snprintf(path, sizeof(path), "%s" OS_PIDFILE "/%s.state", isChroot() ? "" : DEFAULTDIR, __local_name);
    snprintf(path_temp, sizeof(path_temp), "%s.temp", path);

    if (fp = fopen(path_temp, "w"), !fp) {
        merror(FOPEN_ERROR, path_temp, errno, strerror(errno));
        w_mutex_unlock(&state_mutex);
        return -1;
    }
#endif

    switch (agent_state.status) {
    case GA_STATUS_PENDING:
        status = "pending";
        break;
    case GA_STATUS_ACTIVE:
        status = "connected";
        break;
    case GA_STATUS_NACTIVE:
        status = "disconnected";
        break;
    default:
        merror("At write_state(): Unknown status (%d)", agent_state.status);
        status = "unknown";
    }

    if (agent_state.last_keepalive) {
        localtime_r(&agent_state.last_keepalive, &tm);
        strftime(last_keepalive, sizeof(last_keepalive), "%Y-%m-%d %H:%M:%S", &tm);
    }

    if (agent_state.last_ack) {
        localtime_r(&agent_state.last_ack, &tm);
        strftime(last_ack, sizeof(last_ack), "%Y-%m-%d %H:%M:%S", &tm);
    }

    fprintf(fp,
        "# State file for %s\n"
        "\n"
        "# Agent status:\n"
        "# - pending:      waiting for get connected.\n"
        "# - connected:    connection established with manager in the last %d seconds.\n"
        "# - disconnected: connection lost or no ACK received in the last %d seconds.\n"
        "status='%s'\n"
        "\n"
        "# Last time a keepalive was sent\n"
        "last_keepalive='%s'\n"
        "\n"
        "# Last time a control message was received\n"
        "last_ack='%s'\n"
        "\n"
        "# Number of generated events\n"
        "msg_count='%u'\n"
        "\n"
        "# Number of messages (events + control messages) sent to the manager\n"
        "msg_sent='%u'\n"
        , __local_name, agt->notify_time, agt->notify_time, status, last_keepalive, last_ack, agent_state.msg_count, agent_state.msg_sent);

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
