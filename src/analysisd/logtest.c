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
    w_logtest_session_t* current_session;

    /* input-ouput */
    w_logtest_request req = {0};
    cJSON* json_response;
    cJSON* json_output;
    char* str_response;
    int error_code;

    while(1) {
        error_code = 0;
        json_response = cJSON_CreateObject();

        /* Wait for client */
        w_mutex_lock(&connection->mutex);

        if (client = accept(connection->sock, (struct sockaddr *)NULL, NULL), client < 0) {
            merror(LOGTEST_ERROR_ACCEPT_CONN, strerror(errno));
            continue;
        }

        w_mutex_unlock(&connection->mutex);

        if (size_msg_received = recv(client, msg_received, OS_MAXSTR - 1, 0), size_msg_received < 0) {
            merror(LOGTEST_ERROR_RECV_MSG, strerror(errno));
            close(client);
            continue;
        }
        msg_received[size_msg_received] = '\0';

        /* Check msg and generate a request */
        if (w_logtest_check_input(msg_received, &req) == -1) {
            cJSON_AddStringToObject(json_response, W_LOGTEST_JSON_CODE,    "-1");
            cJSON_AddStringToObject(json_response, W_LOGTEST_JSON_MESSAGE, "Error msg");
            goto response;
        }

        /* Process */
        current_session = w_logtest_get_session(&req);
        json_output = w_logtest_process_log(&req, current_session);

        /* Generate response */

        if (cJSON_AddStringToObject(json_response, W_LOGTEST_JSON_TOKEN, req.token) == NULL) {
            merror("(0000) %s error creating json response", W_LOGTEST_JSON_TOKEN);
            goto cleanup;
        }

        // @TODO Check alert
        if (cJSON_AddBoolToObject(json_response, W_LOGTEST_JSON_ALERT, 0) == NULL) {
            merror("(0000) %s error creating json response", W_LOGTEST_JSON_TOKEN);
            goto cleanup;
        }

        // @TODO Generate msg of info/warn/err
        if (cJSON_AddStringToObject(json_response, W_LOGTEST_JSON_MESSAGE, "Maybe a msg") == NULL) {
            merror("(0000) %s error creating json response", W_LOGTEST_JSON_TOKEN);
            goto cleanup;
        }

        // @TODO Set code msg
        if (cJSON_AddNumberToObject(json_response, W_LOGTEST_JSON_CODE, error_code) == NULL) {
            merror("(0000) %s error creating json response", W_LOGTEST_JSON_TOKEN);
            goto cleanup;
        }

        cJSON_AddItemToObject(json_response, W_LOGTEST_JSON_OUTPUT, json_output);

  
response:

        if(isDebug()){
            str_response = cJSON_Print(json_response);
        }else{
            str_response = cJSON_PrintUnformatted(json_response);
        }

        if (send(client, str_response, strlen(str_response) + 1, 0) == -1) {
             merror(LOGTEST_ERROR_RESPONSE, req.token, errno, strerror(errno));
        }

cleanup:
        w_logtest_free_request(&req);
        os_free(str_response);
        cJSON_Delete(json_response);
        close(client);
    }

    return NULL;
}

// Dummy init
w_logtest_session_t *w_logtest_initialize_session(char *token) {
    w_logtest_session_t *session;
    os_calloc(1, sizeof(w_logtest_session_t), session);
    if(OSHash_Add(w_logtest_sessions, token, session) != 2){
        merror_exit("Error to add client");
    }

    return session;
}


cJSON* w_logtest_process_log(w_logtest_request* req, w_logtest_session_t* session) {
    return NULL;
}

void w_logtest_remove_session(const char *token) {

}


void *w_logtest_check_inactive_sessions(__attribute__((unused)) void * arg) {
    OSHashNode *hash_node;
    unsigned int inode_it = 0;
    time_t current_time;

    while (1) {

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

int w_logtest_check_input(char* input_json, w_logtest_request* req) {
    int ret = OS_INVALID; 

    /* Parse raw JSON input */
    cJSON* root;
    cJSON* location;
    cJSON* log_format;
    cJSON* event;
    cJSON* token;
    const char* jsonErrPtr;

    root = cJSON_ParseWithOpts(input_json, &jsonErrPtr, 0);
    if (!root) {
        mdebug1(LOGTEST_ERROR_JSON_PARSE);
        mdebug1(LOGTEST_ERROR_JSON_PARSE_POS, (int)(jsonErrPtr - input_json),
                (char*)(jsonErrPtr - 10 < input_json ? input_json : jsonErrPtr - 10));

        goto cleanup;
    }

    /* Check JSON fields */
    location = cJSON_GetObjectItemCaseSensitive(root, W_LOGTEST_JSON_LOCATION);
    if (!(cJSON_IsString(location) && (location->valuestring != NULL))) {
        
        mdebug1(LOGTEST_ERROR_JSON_REQUIRED_SFIELD, W_LOGTEST_JSON_LOCATION);
        goto cleanup;
    }

    log_format = cJSON_GetObjectItemCaseSensitive(root, W_LOGTEST_JSON_LOGFORMAT);
    if (!(cJSON_IsString(log_format) && (log_format->valuestring != NULL))) {

        mdebug1(LOGTEST_ERROR_JSON_REQUIRED_SFIELD, W_LOGTEST_JSON_LOGFORMAT);
        goto cleanup;
    }

    event = cJSON_GetObjectItemCaseSensitive(root, W_LOGTEST_JSON_EVENT);
    if (!(cJSON_IsString(event) && (event->valuestring != NULL))) {
        
        mdebug1(LOGTEST_ERROR_JSON_REQUIRED_SFIELD, W_LOGTEST_JSON_EVENT);
        goto cleanup;
    }

    token = cJSON_GetObjectItemCaseSensitive(root, W_LOGTEST_JSON_TOKEN);
    req->token = NULL;
    if (cJSON_IsString(token) && (token->valuestring != NULL)) {

        if (strlen(token->valuestring) != W_LOGTEST_TOKEN_LENGH) {
            mdebug1(LOGTEST_ERROR_TOKEN_INVALID, token->valuestring);
        } else {
            os_strdup(token->valuestring, req->token);
        }
    }

    os_strdup(location->valuestring, req->location);
    os_strdup(log_format->valuestring, req->log_format);
    os_strdup(event->valuestring, req->event);

    ret = OS_SUCCESS;

cleanup:
    cJSON_Delete(root);
    return ret;
}

void w_logtest_free_request(w_logtest_request* req) {

    os_free(req->event);
    os_free(req->token);
    os_free(req->location);
    os_free(req->log_format);
}

w_logtest_session_t* w_logtest_get_session(w_logtest_request* req){
    
    w_logtest_session_t* session = NULL;

    /* Search an active session */
    if (req->token) {
        if (session = OSHash_Get(w_logtest_sessions, req->token), session) {
            session->last_connection = time(NULL);
            return session;
        }
        mdebug1("%s", LOGTEST_WARN_TOKEN_EXPIRED);
    }

    /* New session */
    do {
        os_free(req->token);
        req->token = w_logtest_generate_token();
    } while (OSHash_Get(w_logtest_sessions, req->token) != NULL);
    mdebug1(LOGTEST_INFO_TOKEN_NEW, req->token);

    session = w_logtest_initialize_session(req->token);
    return session;
}

char* w_logtest_generate_token() {

    char* str_token;
    int32_t int_token;

    os_malloc(W_LOGTEST_TOKEN_LENGH + 1, str_token);
    randombytes((void*)&int_token, sizeof(int32_t));
    snprintf(str_token, W_LOGTEST_TOKEN_LENGH + 1, "%08x", int_token);

    return str_token;
}
