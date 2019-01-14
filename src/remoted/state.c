/* Remoted state management functions
 * May 25, 2018
 *
 * Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "remoted.h"
#include <pthread.h>

remoted_state_t remoted_state = {0, 0, 0, 0, 0};
static pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;
static int rem_write_state();
static char *refresh_time;

void * rem_state_main() {
    int interval = getDefine_Int("remoted", "state_interval", 0, 86400);

    if (!interval) {
        minfo("State file is disabled.");
        return NULL;
    }

    os_calloc(30, sizeof(char), refresh_time);
    if (interval < 60) {
        snprintf(refresh_time, 30, "Updated every %i seconds.", interval);
    } else if (interval < 3600) {
        snprintf(refresh_time, 30, "Updated every %i minutes.", interval/60);
    } else {
        snprintf(refresh_time, 30, "Updated every %i hours.", interval/3600);
    }

    mdebug1("State file updating thread started.");

    while (1) {
        rem_write_state();
        sleep(interval);
    }

    return NULL;
}

int rem_write_state() {
    FILE * fp;
    char path[PATH_MAX + 1];
    char path_temp[PATH_MAX + 1];
    remoted_state_t state_cpy;

    if (!strcmp(__local_name, "unset")) {
        merror("At write_state(): __local_name is unset.");
        return -1;
    }

    mdebug2("Updating state file.");

    snprintf(path, sizeof(path), "%s" OS_PIDFILE "/%s.state", isChroot() ? "" : DEFAULTDIR, __local_name);
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
        "evt_count='%u'\n"
        "\n"
        "# Control messages received\n"
        "ctrl_msg_count='%u'\n"
        "\n"
        "# Discarded messages\n"
        "discarded_count='%u'\n"
        "\n"
        "# Messages sent\n"
        "msg_sent='%u'\n",
        __local_name, refresh_time, rem_get_qsize(), rem_get_tsize(), state_cpy.tcp_sessions,
        state_cpy.evt_count, state_cpy.ctrl_msg_count, state_cpy.discarded_count, state_cpy.msg_sent);

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

void rem_inc_evt() {
    w_mutex_lock(&state_mutex);
    remoted_state.evt_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_ctrl_msg() {
    w_mutex_lock(&state_mutex);
    remoted_state.ctrl_msg_count++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_msg_sent() {
    w_mutex_lock(&state_mutex);
    remoted_state.msg_sent++;
    w_mutex_unlock(&state_mutex);
}

void rem_inc_discarded() {
    w_mutex_lock(&state_mutex);
    remoted_state.discarded_count++;
    w_mutex_unlock(&state_mutex);
}
