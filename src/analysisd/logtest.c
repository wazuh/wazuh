/* Copyright (C) 2015-2020, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "logtest.h"


void *w_logtest_init() {

    w_logtest_connection_t connection;

    if (w_logtest_init_parameters() == OS_INVALID) {
        merror(LOGTEST_ERROR_INV_CONF);
        return NULL;
    }

    if (!w_logtest_conf.enabled) {
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

    if (!OSHash_setSize(w_logtest_sessions, w_logtest_conf.max_sessions*2)) {
        merror(LOGTEST_ERROR_SIZE_HASH);
        return NULL;
    }

    w_mutex_init(&connection.mutex, NULL);

    minfo(LOGTEST_INITIALIZED);

    for (int i = 1; i < w_logtest_conf.threads; i++) {
        w_create_thread(w_logtest_main, &connection);
    }

    w_create_thread(w_logtest_check_inactive_sessions, NULL);
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

    w_logtest_conf.enabled = true;
    w_logtest_conf.threads = LOGTEST_THREAD;
    w_logtest_conf.max_sessions = LOGTEST_MAX_SESSIONS;
    w_logtest_conf.session_timeout = LOGTEST_SESSION_TIMEOUT;

    if (ReadConfig(modules, OSSECCONF, NULL, NULL) < 0) {
        return OS_INVALID;
    }

    return OS_SUCCESS;
}


void *w_logtest_main(w_logtest_connection_t *connection) {

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


void w_logtest_process_log(char *token) {

}


w_logtest_session_t *w_logtest_initialize_session(char *token, char **msg_error) {

    w_logtest_session_t *session;

    char **files;

    os_calloc(1, sizeof(w_logtest_session_t), session);

    session->token = token;
    session->last_connection = time(NULL);

    /* Create list to save previous events */
    os_calloc(1, sizeof(EventList), session->eventlist);
    OS_CreateEventList(Config.memorysize, session->eventlist);

    /* Load decoders */
    session->decoderlist_forpname = NULL;
    session->decoderlist_nopname = NULL;

    files = Config.decoders;

    while (files && *files) {
        if (!ReadDecodeXML(*files, &session->decoderlist_forpname, &session->decoderlist_nopname)) {
            return NULL;
        }
        files++;
    }

    /* Load CDB list */
    session->cdblistnode = NULL;
    session->cdblistrule = NULL;

    files = Config.lists;

    while (files && *files) {
        if (Lists_OP_LoadList(*files, &session->cdblistnode) < 0) {
            return NULL;
        }
        files++;
    }

    Lists_OP_MakeAll(0, 0, &session->cdblistnode);

    /* Load rules */
    session->rule_list = NULL;

    files = Config.includes;

    while (files && *files) {
        if (Rules_OP_ReadRules(*files, &session->rule_list, &session->cdblistnode, &session->eventlist) < 0) {
            return NULL;
        }
        files++;
    }

    /* Associate rules and CDB lists */
    OS_ListLoadRules(&session->cdblistnode, &session->cdblistrule);

    /* _setlevels */
    _setlevels(session->rule_list, 0);

    /* Creating rule hash */
    if (session->g_rules_hash = OSHash_Create(), !session->g_rules_hash) {
        return NULL;
    }

    AddHash_Rule(session->rule_list);

    /* Initiate the FTS list */
    if (!w_logtest_fts_init(&session->fts_list, &session->fts_store)) {
        return NULL;
    }

    /* Initialize the Accumulator */
    if (!Accumulate_Init(&session->acm_store, &session->acm_lookups, &session->acm_purge_ts)) {
        return NULL;
    }

    return session;
}


void w_logtest_remove_session(char *token) {

    w_logtest_session_t *session;

    /* Remove session from hash */
    if (session = OSHash_Delete_ex(w_logtest_sessions, token), !session) {
        return;
    }

    /* Remove rule list and rule hash */
    os_remove_rules_list(session->rule_list);
    OSHash_Free(session->g_rules_hash);

    /* Remove decoder list */
    os_remove_decoders_list(session->decoderlist_forpname, session->decoderlist_nopname);

    /* Remove cdblistnode and cdblistrule */
    os_remove_cdblist(&session->cdblistnode);
    os_remove_cdbrules(&session->cdblistrule);

    /* Remove list of previous events */
    os_remove_eventlist(session->eventlist);

    /* Remove fts list and hash */
    OSHash_Free(session->fts_store);
    os_free(session->fts_list);

    /* Remove accumulator hash */
    OSHash_Free(session->acm_store);

    os_free(session);
}


void *w_logtest_check_inactive_sessions(__attribute__((unused)) void * arg) {

    OSHashNode *hash_node;
    unsigned int inode_it = 0;
    time_t current_time;

    while (FOREVER()) {

        sleep(w_logtest_conf.session_timeout);

        hash_node = OSHash_Begin(w_logtest_sessions, &inode_it);

        while (hash_node) {
            char *token_session;
            w_logtest_session_t *session = NULL;

            token_session = hash_node->key;
            session = hash_node->data;

            current_time = time(NULL);
            if (difftime(current_time, session->last_connection) >= w_logtest_conf.session_timeout) {
                w_logtest_remove_session(token_session);
            }

            hash_node = OSHash_Next(w_logtest_sessions, &inode_it, hash_node);
        }

    }

    return NULL;

}


int w_logtest_fts_init(OSList **fts_list, OSHash **fts_store) {

    int list_size = getDefine_Int("analysisd", "fts_list_size", 12, 512);

    if (*fts_list = OSList_Create(), *fts_list == NULL) {
        merror(LIST_ERROR);
        return 0;
    }

    if (!OSList_SetMaxSize(*fts_list, list_size)) {
        merror(LIST_SIZE_ERROR);
        return 0;
    }

    if (*fts_store = OSHash_Create(), *fts_store == NULL) {
        merror(HASH_ERROR);
        return 0;
    }

    if (!OSHash_setSize(*fts_store, 2048)) {
        merror(LIST_SIZE_ERROR);
        return 0;
    }

    return 1;
}
