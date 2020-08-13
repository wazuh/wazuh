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
    pthread_t * logtest_threads = NULL;

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

    int num_extra_threads = w_logtest_conf.threads - 1;

    if (num_extra_threads > 0) {
        os_calloc(num_extra_threads, sizeof(pthread_t), logtest_threads);

        for (int i = 0; i < num_extra_threads; i++) {
            if(CreateThreadJoinable(logtest_threads + i, w_logtest_clients_handler, &connection)){
                merror_exit(THREAD_ERROR);
            }
        }
    }

    w_create_thread(w_logtest_check_inactive_sessions, NULL);
    w_logtest_clients_handler(&connection);

    for (int i = 0; i < num_extra_threads; i++) {
        pthread_join(logtest_threads[i], NULL);
    }

    os_free(logtest_threads)

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

void * w_logtest_clients_handler(w_logtest_connection_t * connection) {

    int client;
    char msg_received[OS_MAXSTR];
    int size_msg_received;
    char * str_response;

    while (FOREVER()) {

        str_response = NULL;

        /* Wait for client */
        w_mutex_lock(&connection->mutex);
        if (client = accept(connection->sock, (struct sockaddr *) NULL, NULL), client < 0) {
            int err_accept = errno;
            w_mutex_unlock(&connection->mutex);
            merror(LOGTEST_ERROR_ACCEPT_CONN, strerror(err_accept));

            /* check if socket is closed */
            if (err_accept == EBADF) {
                return NULL;
            }
            continue;
        }
        w_mutex_unlock(&connection->mutex);

        if (size_msg_received = recv(client, msg_received, OS_MAXSTR - 1, 0), size_msg_received < 0) {
            merror(LOGTEST_ERROR_RECV_MSG, strerror(errno));
            close(client);
            continue;
        }
        msg_received[size_msg_received] = '\0';

        if (str_response = w_logtest_process_request(msg_received), !str_response) {
            return NULL;
        }

        if (send(client, str_response, strlen(str_response) + 1, 0) == -1) {
            merror(LOGTEST_ERROR_RESPONSE, errno, strerror(errno));
        }

        /* Frees resourse of requeset */
        os_free(str_response);
        close(client);
    }

    return NULL;
}

w_logtest_session_t *w_logtest_initialize_session(char *token, OSList* list_msg) {

    w_logtest_session_t *session;

    char **files;

    os_calloc(1, sizeof(w_logtest_session_t), session);

    session->token = token;
    session->expired = false;
    session->last_connection = time(NULL);
    w_mutex_init(&session->mutex, NULL);

    /* Create list to save previous events */
    os_calloc(1, sizeof(EventList), session->eventlist);
    OS_CreateEventList(Config.memorysize, session->eventlist);

    /* Load decoders */
    session->decoderlist_forpname = NULL;
    session->decoderlist_nopname = NULL;

    files = Config.decoders;

    while (files && *files) {
        if (!ReadDecodeXML(*files, &session->decoderlist_forpname, &session->decoderlist_nopname, list_msg)) {
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
        if (Rules_OP_ReadRules(*files, &session->rule_list, &session->cdblistnode, 
                            &session->eventlist, list_msg) < 0) {
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

    /* Remove session */
    w_mutex_destroy(&session->mutex);
    os_free(session->token);
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

            w_mutex_lock(&session->mutex);
            current_time = time(NULL);
            if (difftime(current_time, session->last_connection) >= w_logtest_conf.session_timeout) {
                session->expired = true;
            }

            w_mutex_unlock(&session->mutex);

            if(session->expired){
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

bool w_logtest_check_input(char * input_json, cJSON ** req, OSList * list_msg) {

    /* Nodes JSON input */
    cJSON * root;
    cJSON * location;
    cJSON * log_format;
    cJSON * event;
    cJSON * token;

    bool retval = true;

    /* Parse raw JSON input */
    const char * jsonErrPtr;
    root = cJSON_ParseWithOpts(input_json, &jsonErrPtr, 0);
    *req = root;
    if (!root) {
        char * slice_json;
        char * pos;

        os_calloc(W_LOGTEST_ERROR_JSON_PARSE_NSTR + 1, sizeof(char), slice_json);
        pos = (char *) (jsonErrPtr - W_LOGTEST_ERROR_JSON_PARSE_NSTR / 2 < input_json
                            ? input_json
                            : jsonErrPtr - W_LOGTEST_ERROR_JSON_PARSE_NSTR / 2);

        snprintf(slice_json, W_LOGTEST_ERROR_JSON_PARSE_NSTR + 1, "%s", pos);

        mdebug1(LOGTEST_ERROR_JSON_PARSE);
        smerror(list_msg, LOGTEST_ERROR_JSON_PARSE);

        mdebug1(LOGTEST_ERROR_JSON_PARSE_POS, (int) (jsonErrPtr - input_json), slice_json);
        smerror(list_msg, LOGTEST_ERROR_JSON_PARSE_POS, (int) (jsonErrPtr - input_json), slice_json);

        os_free(slice_json);
        return false;
    }

    /* Check JSON fields */
    location = cJSON_GetObjectItemCaseSensitive(root, W_LOGTEST_JSON_LOCATION);
    if (!(cJSON_IsString(location) && (location->valuestring != NULL))) {

        mdebug1(LOGTEST_ERROR_JSON_REQUIRED_SFIELD, W_LOGTEST_JSON_LOCATION);
        smerror(list_msg, LOGTEST_ERROR_JSON_REQUIRED_SFIELD, W_LOGTEST_JSON_LOCATION);
        retval = false;
    }

    log_format = cJSON_GetObjectItemCaseSensitive(root, W_LOGTEST_JSON_LOGFORMAT);
    if (!(cJSON_IsString(log_format) && (log_format->valuestring != NULL))) {

        mdebug1(LOGTEST_ERROR_JSON_REQUIRED_SFIELD, W_LOGTEST_JSON_LOGFORMAT);
        smerror(list_msg, LOGTEST_ERROR_JSON_REQUIRED_SFIELD, W_LOGTEST_JSON_LOGFORMAT);
        retval = false;
    }

    event = cJSON_GetObjectItemCaseSensitive(root, W_LOGTEST_JSON_EVENT);
    if (!(cJSON_IsString(event) && (event->valuestring != NULL))) {

        mdebug1(LOGTEST_ERROR_JSON_REQUIRED_SFIELD, W_LOGTEST_JSON_EVENT);
        smerror(list_msg, LOGTEST_ERROR_JSON_REQUIRED_SFIELD, W_LOGTEST_JSON_EVENT);
        retval = false;
    }

    token = cJSON_GetObjectItemCaseSensitive(root, W_LOGTEST_JSON_TOKEN);
    if (cJSON_IsString(token) && token->valuestring != NULL && strlen(token->valuestring) != W_LOGTEST_TOKEN_LENGH) {

        mdebug1(LOGTEST_ERROR_TOKEN_INVALID, token->valuestring);
        smwarn(list_msg, LOGTEST_ERROR_TOKEN_INVALID, token->valuestring);
        cJSON_DeleteItemFromObjectCaseSensitive(root, W_LOGTEST_JSON_TOKEN);
    }

    return retval;
}

w_logtest_session_t * w_logtest_get_session(cJSON * req, OSList * list_msg) {

    w_logtest_session_t * session = NULL;

    cJSON * j_token;
    char * s_token = NULL;

    if (j_token = cJSON_GetObjectItemCaseSensitive(req, W_LOGTEST_JSON_TOKEN), j_token) {
        s_token = j_token->valuestring;
    }

    /* Search an active session */
    if (s_token) {
        if (session = OSHash_Get(w_logtest_sessions, s_token), session) {

            w_mutex_lock(&session->mutex);
            if (!session->expired) {
                session->last_connection = time(NULL);
                w_mutex_unlock(&session->mutex);
                return session;
            }
            w_mutex_unlock(&session->mutex);
        }

        mdebug1(LOGTEST_WARN_TOKEN_EXPIRED, s_token);
        smwarn(list_msg, LOGTEST_WARN_TOKEN_EXPIRED, s_token);
    }

    /* New session */
    s_token = NULL;
    do {
        os_free(s_token);
        s_token = w_logtest_generate_token();
    } while (OSHash_Get(w_logtest_sessions, s_token) != NULL);

    mdebug1(LOGTEST_INFO_TOKEN_NEW, s_token);
    sminfo(list_msg, LOGTEST_INFO_TOKEN_NEW, s_token);

    session = w_logtest_initialize_session(s_token, list_msg);
    if (session) {
        OSHash_Add(w_logtest_sessions, s_token, session);
    } else {
        smerror(list_msg, LOGTEST_ERROR_INITIALIZE_SESSION, s_token);
        mdebug1(LOGTEST_ERROR_INITIALIZE_SESSION, s_token);
    }

    return session;
}

char * w_logtest_generate_token() {

    char * str_token;
    int32_t int_token;

    os_calloc(W_LOGTEST_TOKEN_LENGH + 1, sizeof(char), str_token);
    randombytes((void *) &int_token, sizeof(int32_t));
    snprintf(str_token, W_LOGTEST_TOKEN_LENGH + 1, "%08x", int_token);

    return str_token;
}

int w_logtest_get_rule_level(cJSON * json_log_processed) {
    cJSON * rule;
    cJSON * level;
    int ret = 0;

    if (!json_log_processed) {
        mdebug1(LOGTEST_INFO_LOG_EMPTY);
        ret = 0;
    } else if (rule = cJSON_GetObjectItemCaseSensitive(json_log_processed, "rule"), !rule) {
        mdebug1(LOGTEST_INFO_LOG_NOALERT);
        ret = 0;
    } else if (level = cJSON_GetObjectItemCaseSensitive(rule, "level"), !level) {
        mdebug1(LOGTEST_INFO_LOG_NOLEVEL);
        ret = 0;
    } else if (cJSON_IsNumber(level)) {
        ret = level->valueint;
    }

    return ret;
}

void w_logtest_add_msg_response(cJSON * response, OSList * list_msg, int * error_code) {

    int ret_level = *error_code;

    OSListNode * node_log_msg;
    cJSON * json_arr_msg;

    if (node_log_msg = OSList_GetFirstNode(list_msg), !node_log_msg) {
        return;
    }
    /* check if exist messages in the response */
    else if (json_arr_msg = cJSON_GetObjectItemCaseSensitive(response, W_LOGTEST_JSON_MESSAGES), !json_arr_msg) {
        json_arr_msg = cJSON_CreateArray();
        cJSON_AddItemToObject(response, W_LOGTEST_JSON_MESSAGES, json_arr_msg);
    }

    while (node_log_msg) {
        cJSON * json_item_message;
        char * json_str_msj = NULL;
        char * raw_msg;

        /* get msg */
        os_analysisd_log_msg_t * data_msg = node_log_msg->data;
        raw_msg = os_analysisd_string_log_msg(data_msg);

        /* Add header and set max level of msgs */
        if (data_msg->level == LOGLEVEL_ERROR) {

            ret_level = W_LOGTEST_RCODE_ERROR_PROCESS;
            wm_strcat(&json_str_msj, "ERROR: ", 0);

        } else if (data_msg->level == LOGLEVEL_WARNING) {

            if (ret_level != W_LOGTEST_RCODE_ERROR_PROCESS) {
                ret_level = W_LOGTEST_RCODE_WARNING;
            }
            wm_strcat(&json_str_msj, "WARNING: ", 0);

        } else {
            wm_strcat(&json_str_msj, "INFO: ", 0);
        }

        /* Add to json array */
        wm_strcat(&json_str_msj, raw_msg, 0);
        json_item_message = cJSON_CreateString(json_str_msj);
        cJSON_AddItemToArray(json_arr_msg, json_item_message);

        /* Cleanup */
        os_free(raw_msg);
        os_free(json_str_msj);
        os_analysisd_free_log_msg(&data_msg);
        OSList_DeleteCurrentlyNode(list_msg);

        node_log_msg = OSList_GetFirstNode(list_msg);
    }

    *error_code = ret_level;
    return;
}

char * w_logtest_process_request(char * raw_request) {

    char * str_response = NULL;
    cJSON * json_request = NULL;
    cJSON * json_response = NULL;
    cJSON * json_log_processed = NULL;

    w_logtest_session_t * current_session = NULL;

    /* error & message handlers */
    int retval = W_LOGTEST_RCODE_SUCCESS;
    OSList * list_msg = OSList_Create();
    if (!list_msg) {
        merror(LIST_ERROR);
        return NULL;
    }
    OSList_SetMaxSize(list_msg, ERRORLIST_MAXSIZE);

    /* Check message and generate a request */
    json_response = cJSON_CreateObject();
    if (!w_logtest_check_input(raw_request, &json_request, list_msg)) {
        retval = W_LOGTEST_RCODE_ERROR_INPUT;
    }

    /* Get session */
    if (retval >= W_LOGTEST_RCODE_SUCCESS) {

        current_session = w_logtest_get_session(json_request, list_msg);
        if (current_session) {
            cJSON_AddStringToObject(json_response, W_LOGTEST_JSON_TOKEN, current_session->token);
        }
    }
    /* Proccess log */
    if (retval >= W_LOGTEST_RCODE_SUCCESS) {

        json_log_processed = w_logtest_process_log(json_request, current_session, list_msg);
        if (json_log_processed) {
            cJSON_AddItemToObject(json_response, W_LOGTEST_JSON_OUTPUT, json_log_processed);
        } else {
            smerror(list_msg, LOGTEST_ERROR_PROCESS_EVENT);
            mdebug1(LOGTEST_ERROR_PROCESS_EVENT);
        }
    }

    /* Check alert level */
    if (retval >= W_LOGTEST_RCODE_SUCCESS) {
        uint8_t rule_level = (uint8_t) w_logtest_get_rule_level(json_log_processed);
        int alert = (Config.logbylevel <= rule_level) ? 1 : 0;
        cJSON_AddBoolToObject(json_response, W_LOGTEST_JSON_ALERT, alert);
    }

    w_logtest_add_msg_response(json_response, list_msg, &retval);
    cJSON_AddNumberToObject(json_response, W_LOGTEST_JSON_CODE, retval);

    str_response = cJSON_PrintUnformatted(json_response);
    cJSON_Delete(json_response);
    cJSON_Delete(json_request);
    os_free(list_msg);

    return str_response;
}

cJSON * w_logtest_process_log(cJSON * req, w_logtest_session_t * session, OSList * list_msg) { return NULL; }
