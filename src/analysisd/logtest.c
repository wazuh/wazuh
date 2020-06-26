/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "logtest.h"

void *w_logtest_init() {

    int connection = 0;

    if (connection = OS_BindUnixDomain(LOGTEST_SOCK, SOCK_STREAM, OS_MAXSTR), connection < 0) {
        merror(LOGTEST_ERROR_BIND_SOCK, LOGTEST_SOCK, errno, strerror(errno));
        return NULL;
    }

    if(all_sessions = OSHash_Create(), !all_sessions) {
        merror(LOGTEST_ERROR_INIT_HASH);
        return NULL;
    }

    w_mutex_init(&logtest_mutex, NULL);

    minfo(LOGTEST_INITIALIZED);

    w_logtest_main(&connection);

    close(connection);
    w_mutex_destroy(&logtest_mutex);

    return NULL;
}


void *w_logtest_main(int *connection) {

    int client;
    char msg_received[OS_MAXSTR];
    int size_msg_received;

    while(1) {

        w_mutex_lock(&logtest_mutex);

        if(client = accept(*connection, (struct sockaddr *)NULL, NULL), client < 0) {
            merror(LOGTEST_ERROR_ACCEPT_CONN, strerror(errno));
            continue;
        }

        w_mutex_unlock(&logtest_mutex);

        if(size_msg_received = recv(client, msg_received, OS_MAXSTR, 0), size_msg_received < 0) {
            merror(LOGTEST_ERROR_RECV_MSG, strerror(errno));
            close(client);
            continue;
        }

        close(client);
    }

    return NULL;
}


void w_logtest_initialize_session(int token) {

}


void w_logtest_process_log(int token) {

}


void w_logtest_remove_session(int token) {

}


void w_logtest_check_active_sessions() {

}
