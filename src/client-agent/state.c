/* Agent state management functions
 * August 2, 2017
 *
 * Copyright (C) 2017 Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "agentd.h"

agent_state_t agent_state;

int update_status(agent_status_t status) {
    agent_state.status = status;
    return write_state();
}

int update_keepalive(time_t curr_time) {
    agent_state.last_keepalive = curr_time;
    return write_state();
}

int update_ack(time_t curr_time) {
    agent_state.last_ack = curr_time;
    return write_state();
}

int write_state() {
    FILE * fp;
    struct tm tm;
    const char * status;
    char path[PATH_MAX + 1];
    char path_temp[PATH_MAX + 1];
    char last_keepalive[1024] = "";
    char last_ack[1024] = "";

    if (!strcmp(__local_name, "unset")) {
        merror("At write_state(): __local_name is unset.");
        return -1;
    }

#ifdef WIN32
    snprintf(path, sizeof(path), "%s.state", __local_name);
#else
    snprintf(path, sizeof(path), "%s" OS_PIDFILE "/%s.state", isChroot() ? "" : DEFAULTDIR, __local_name);
#endif

    snprintf(path_temp, sizeof(path_temp), "%s.temp", path);

    if (fp = fopen(path_temp, "w"), !fp) {
        merror(FOPEN_ERROR, path_temp, errno, strerror(errno));
        return -1;
    }

    switch (agent_state.status) {
    case ST_PENDING:
        status = "pending";
        break;
    case ST_CONNECTED:
        status = "connected";
        break;
    case ST_DISCONNECTED:
        status = "disconnected";
        break;
    default:
        merror("At write_state(): Unknown status (%d)", agent_state.status);
        status = "unknown";
    }

    if (agent_state.last_keepalive) {
        localtime_r(&agent_state.last_keepalive, &tm);
        strftime(last_keepalive, sizeof(last_keepalive), "%F %T", &tm);
    }

    if (agent_state.last_ack) {
        localtime_r(&agent_state.last_ack, &tm);
        strftime(last_ack, sizeof(last_ack), "%F %T", &tm);
    }

    if (fp = fopen(path_temp, "w"), !fp) {
        merror(FOPEN_ERROR, path_temp, errno, strerror(errno));
        return -1;
    }

    fprintf(fp,
        "# State file for %s\n"
        "\n"
        "# Agent status:\n"
        "# - pending:      waiting for get connected.\n"
        "# - connected:    connection stablished with manager in the last 30 minutes.\n"
        "# - disconnected: connection lost or no ACK received in the last 30 minutes.\n"
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
        , __local_name, status, last_keepalive, last_ack, agent_state.msg_count, agent_state.msg_sent);

    fclose(fp);

    if (rename(path_temp, path) < 0) {
        merror("Renaming %s to %s: %s", path_temp, path, strerror(errno));
        unlink(path_temp);
        return -1;
    } else {
        return 0;
    }
}
