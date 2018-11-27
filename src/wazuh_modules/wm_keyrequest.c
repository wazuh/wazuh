/*
 * Wazuh Module for remote key requests
 * Copyright (C) 2018 Wazuh Inc.
 * November 25, 2018.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include <os_net/os_net.h>
#include "shared.h"

#define minfo(format, ...) mtinfo(WM_KEY_REQUEST_LOGTAG, format, ##__VA_ARGS__)
#define mwarn(format, ...) mtwarn(WM_KEY_REQUEST_LOGTAG, format, ##__VA_ARGS__)
#define merror(format, ...) mterror(WM_KEY_REQUEST_LOGTAG, format, ##__VA_ARGS__)
#define mdebug1(format, ...) mtdebug1(WM_KEY_REQUEST_LOGTAG, format, ##__VA_ARGS__)
#define mdebug2(format, ...) mtdebug2(WM_KEY_REQUEST_LOGTAG, format, ##__VA_ARGS__)

static void * wm_key_request_main(wm_krequest_t * data);   // Module main function. It won't return
static void wm_key_request_destroy(wm_krequest_t * data);  // Destroy data
cJSON *wm_key_request_dump(const wm_krequest_t * data);     // Read config

void * w_request_thread(const wm_krequest_t *data);

// Dispatch request. Write the output into the same input buffer.
static int wm_key_request_dispatch(char * buffer,const wm_krequest_t * data);

/* Decode rootcheck input queue */
static w_queue_t * request_queue;

static OSHash *request_hash = NULL;

const char *script_params[2] = { "id", "ip" };

const wm_context WM_KEY_REQUEST_CONTEXT = {
    "key-polling",
    (wm_routine)wm_key_request_main,
    (wm_routine)wm_key_request_destroy,
    (cJSON * (*)(const void *))wm_key_request_dump
};

typedef enum _request_type{
    W_TYPE_ID,W_TYPE_IP
} _request_type_t;

// Module main function. It won't return
void * wm_key_request_main(wm_krequest_t * data) {
    int sock;
    int recv;
    unsigned int i;
    char buffer[OS_MAXSTR + 1];
    char * copy;

    // If module is disabled, exit
    if (data->enabled) {
        minfo("Module started");
    } else {
        minfo("Module disabled. Exiting.");
        pthread_exit(NULL);
    }

    /* Ignore SIGPIPE, it will be detected on recv */
    signal(SIGPIPE, SIG_IGN);

    /* Init the request hash table */
    request_hash = OSHash_Create();

    if (!request_hash) {
        merror(LIST_ERROR);
        pthread_exit(NULL);
    }

    /* Init the decode rootcheck queue input */
    request_queue = queue_init(data->queue_size);

    for(i = 0; i < data->threads;i++){
        w_create_thread(w_request_thread,data);
    }

    if ((sock = StartMQ(WM_KEY_REQUEST_SOCK_PATH, READ)) < 0) {
        merror_exit(QUEUE_ERROR, WM_KEY_REQUEST_SOCK_PATH, strerror(errno));
    }

    while (1) {

        if (recv = OS_RecvUnix(sock, OS_MAXSTR, buffer),recv) {

            if(OSHash_Get_ex(request_hash,buffer)){
                mdebug1("Request '%s' already being processed. Discarting...",buffer);
                continue;
            }

            OSHash_Add_ex(request_hash,buffer,(void *)1);

            os_strdup(buffer, copy);

            if(queue_full(request_queue)){
                mdebug1("Request queue is full. Discarting...");
                os_free(copy);
                OSHash_Delete_ex(request_hash,buffer);
                continue;
            }

            int result = queue_push_ex(request_queue,copy);

            if(result < 0){
                mdebug1("Request queue is full. Discarting...");
                os_free(copy);
                OSHash_Delete_ex(request_hash,buffer);
                continue;
            }
        }
    }
    return NULL;
}

int wm_key_request_dispatch(char * buffer, const wm_krequest_t * data) {
    char * request;
    char * tmp_buffer;
    char *output;
    int result_code = 0;
    int header_length = 3;
    cJSON *agent_infoJSON;
    _request_type_t type;

    tmp_buffer = buffer;

    // Get the type of request
    if(strncmp("ip:",tmp_buffer,header_length) == 0) {
        type = W_TYPE_IP;
    }else if(strncmp("id:",tmp_buffer,header_length) == 0){
        type = W_TYPE_ID;
    } else {
        mdebug1("Wrong type of request");
        OSHash_Delete_ex(request_hash,buffer);
        return -1;
    }

    switch (type) {
        case W_TYPE_ID:
            tmp_buffer+=header_length;
            request = tmp_buffer;

            if(strlen(request) > 8) {
                mdebug1(" Agent ID is too long");
                OSHash_Delete_ex(request_hash,buffer);
                return -1;
            }
            break;

        case W_TYPE_IP:
            tmp_buffer+=3;
            request = tmp_buffer;

            if(strlen(request) > 19) {
                mdebug1("Agent IP is too long");
                OSHash_Delete_ex(request_hash,buffer);
                return -1;
            }
            break;

        default:
            mdebug1("Invalid request");
            OSHash_Delete_ex(request_hash,buffer);
            return -1;
    }

    // Run external query
    mdebug1("Getting key from script '%s'", data->script);
    
    char *command = NULL;
    os_calloc(OS_MAXSTR + 1,sizeof(char),command);

    if(snprintf(command,OS_MAXSTR,"%s %s %s",data->script,script_params[type],request) > OS_MAXSTR) {
        mdebug1("Request is too long.");
        os_free(command);
        OSHash_Delete_ex(request_hash,buffer);
        return -1;
    }

    if (wm_exec(command, &output, &result_code, data->timeout, NULL) < 0) {
        mdebug1("At wm_key_request_dispatch(): Error executing script [%s]", data->script);
        os_free(command);
        OSHash_Delete_ex(request_hash,buffer);
        return -1;
    } else {
        agent_infoJSON = cJSON_Parse(output);

        if (!agent_infoJSON) {
            mdebug1("Error parsing JSON event. %s", cJSON_GetErrorPtr());
        } else {

            int error = 0;
            cJSON *error_message = NULL;
            cJSON *data_json = NULL;
            cJSON *agent_id = NULL;
            cJSON *agent_name = NULL;
            cJSON *agent_address = NULL;
            cJSON *agent_key = NULL;
            char id[257 + 1] = { '\0' };

            cJSON *json_field;

            if (json_field = cJSON_GetObjectItem(agent_infoJSON,"error"), !json_field) {
                mdebug1("Malformed JSON output received. No 'error' field found");
                cJSON_Delete (agent_infoJSON);
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                os_free(output);
                return -1;
            }

            error = json_field->valueint;

            if(error) {
                error_message = cJSON_GetObjectItem(agent_infoJSON, "message");
                if (!error_message) {
                    mdebug1("Malformed JSON output received. No 'message' field found");
                    cJSON_Delete (agent_infoJSON);
                    os_free(command);
                    OSHash_Delete_ex(request_hash,buffer);
                    os_free(output);
                    return -1;
                }
                merror("%s",error_message->valuestring);
                cJSON_Delete (agent_infoJSON);
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                os_free(output);
                return -1;
            }

            data_json = cJSON_GetObjectItem(agent_infoJSON, "data");
            if (!data_json) {
                mdebug1("Agent data not found.");
                cJSON_Delete (agent_infoJSON);
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                os_free(output);
                return -1;
            }

            agent_id = cJSON_GetObjectItem(data_json, "id");
            if (!agent_id) {
                mdebug1("Agent ID not found.");
                cJSON_Delete (agent_infoJSON);
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                os_free(output);
                return -1;
            }

            agent_name = cJSON_GetObjectItem(data_json, "name");
            if (!agent_name) {
                mdebug1("Agent name not found.");
                cJSON_Delete (agent_infoJSON);
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                os_free(output);
                return -1;
            }

            agent_address = cJSON_GetObjectItem(data_json, "ip");
            if (!agent_address) {
                mdebug1("Agent address not found.");
                cJSON_Delete (agent_infoJSON);
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                os_free(output);
                return -1;
            }

            agent_key = cJSON_GetObjectItem(data_json, "key");
            if (!agent_key) {
                mdebug1("Agent key not found.");
                cJSON_Delete (agent_infoJSON);
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                os_free(output);
                return -1;
            }

            int sock;
            if (sock = auth_connect(), sock < 0) { 
                mdebug1("Could not connect to authd socket. Is authd running?");
            } else {
                auth_add_agent(sock,id,agent_name->valuestring,agent_address->valuestring,agent_key->valuestring,1,1,agent_id->valuestring,0);
                close(sock);
            }

            cJSON_Delete(agent_infoJSON);
        }
        os_free(output);
    }
    OSHash_Delete_ex(request_hash,buffer);
    os_free(command);

    return 0;
}

// Destroy data
void wm_key_request_destroy(wm_krequest_t * data) {
    os_free(data);
}

cJSON *wm_key_request_dump(const wm_krequest_t *data) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd,"enabled","yes");

    if(data->timeout){
        cJSON_AddNumberToObject(wm_wd,"timeout",data->timeout);
    }

    if(data->script){
        cJSON_AddStringToObject(wm_wd,"script",data->script);
    }

    if(data->threads){
        cJSON_AddNumberToObject(wm_wd,"threads",data->threads);
    }

    if(data->queue_size){
        cJSON_AddNumberToObject(wm_wd,"queue_size",data->queue_size);
    }

    cJSON_AddItemToObject(root,"key-polling",wm_wd);
    return root;
}

void * w_request_thread(const wm_krequest_t *data) {
    char *msg = NULL;

    while(1){

        /* Receive request from queue */
        if (msg = queue_pop_ex(request_queue), msg) {

            /* Dispatch the request */
            if(wm_key_request_dispatch(msg,data) < 0) {
                mdebug1("At w_request_thread(): Error getting external key");
            }
            os_free(msg);
        }
    }
}