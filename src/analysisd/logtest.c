/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "logtest.h"


/**
 * @brief Mutex to prevent race condition in accept syscall.
 */
static pthread_mutex_t mutex;


void *w_logtest_init() {

    w_logtest_connection connection;

    if(w_logtest_init_parameters() == OS_INVALID) {
        merror(LOGTEST_ERROR_INV_CONF);
        return NULL;
    }

    if(!strcmp(logtest_conf.enabled, "no")) {
        minfo(LOGTEST_DISABLED);
        return NULL;
    }

    if (connection.sock = OS_BindUnixDomain(LOGTEST_SOCK, SOCK_STREAM, OS_MAXSTR), connection.sock < 0) {
        merror(LOGTEST_ERROR_BIND_SOCK, LOGTEST_SOCK, errno, strerror(errno));
        return NULL;
    }

    if (w_logtest_sessions = OSHash_Create(), !w_logtest_sessions) {
        merror(LOGTEST_ERROR_INIT_HASH);
        return NULL;
    }

    w_mutex_init(&connection.mutex, NULL);

    minfo(LOGTEST_INITIALIZED);

    for(int i = 1; i < logtest_conf.threads; i++) {
        w_create_thread(w_logtest_main, &connection);
    }

    w_logtest_main(&connection);

    close(connection.sock);
    if (unlink(LOGTEST_SOCK)) {
        merror(DELETE_ERROR, LOGTEST_SOCK, errno, strerror(errno));
    }

    w_mutex_destroy(&connection.mutex);

    return NULL;
}


int w_logtest_init_parameters() {

    int modules = CLOGTEST;

    logtest_conf.threads = LOGTEST_THREAD;
    logtest_conf.max_sessions = LOGTEST_MAX_SESSIONS;
    logtest_conf.session_timeout = LOGTEST_SESSION_TIMEOUT;

    os_calloc(4, sizeof(char), logtest_conf.enabled);
    os_strdup("yes", logtest_conf.enabled);

    if (ReadConfig(modules, OSSECCONF, NULL, NULL) < 0) {
        return OS_INVALID;
    }

    return OS_SUCCESS;
}


void *w_logtest_main(w_logtest_connection *connection) {

    int client;
    char msg_received[OS_MAXSTR];
    int size_msg_received;

    while(1) {

        w_mutex_lock(&connection->mutex);

        if (client = accept(connection->sock, (struct sockaddr *)NULL, NULL), client < 0) {
            merror(LOGTEST_ERROR_ACCEPT_CONN, strerror(errno));
            continue;
        }

        w_mutex_unlock(&connection->mutex);

        if (size_msg_received = recv(client, msg_received, OS_MAXSTR, 0), size_msg_received < 0) {
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
