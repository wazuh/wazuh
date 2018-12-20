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

#ifndef WIN32

#include "wmodules.h"
#include <os_net/os_net.h>
#include "shared.h"

#define RELAUNCH_TIME 10

#undef minfo
#undef mwarn
#undef merror
#undef mdebug1
#undef mdebug2

#define minfo(msg, ...) _mtinfo(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mwarn(msg, ...) _mtwarn(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define merror(msg, ...) _mterror(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug1(msg, ...) _mtdebug1(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)
#define mdebug2(msg, ...) _mtdebug2(WM_KEY_REQUEST_LOGTAG, __FILE__, __LINE__, __func__, msg, ##__VA_ARGS__)

static void * wm_key_request_main(wm_krequest_t * data);   // Module main function. It won't return
static void wm_key_request_destroy(wm_krequest_t * data);  // Destroy data
cJSON *wm_key_request_dump(const wm_krequest_t * data);     // Read config

void * w_request_thread(const wm_krequest_t *data);

// Dispatch request. Write the output into the same input buffer.
static int wm_key_request_dispatch(char * buffer,const wm_krequest_t * data);

static int external_socket_connect(char *socket_path, int repsonse_timeout);
static void launch_socket(char *exec_path);

/* Decode rootcheck input queue */
static w_queue_t * request_queue;

static OSHash *request_hash = NULL;

const char *exec_params[2] = { "id", "ip" };

const wm_context WM_KEY_REQUEST_CONTEXT = {
    KEY_WM_NAME,
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

    /* Init the request hash table */
    request_hash = OSHash_Create();

    if (!request_hash) {
        merror(LIST_ERROR);
        pthread_exit(NULL);
    }

    /* Init the queue input */
    request_queue = queue_init(data->queue_size);

    if ((sock = StartMQ(WM_KEY_REQUEST_SOCK_PATH, READ)) < 0) {
        merror_exit(QUEUE_ERROR, WM_KEY_REQUEST_SOCK_PATH, strerror(errno));
    }

    for(i = 0; i < data->threads;i++){
        w_create_thread(w_request_thread,data);
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
            tmp_buffer+=header_length;
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

    char *command = NULL;
    os_calloc(OS_MAXSTR + 1,sizeof(char),command);

    if(snprintf(command, OS_MAXSTR, "%s %s %s", data->exec_path, exec_params[type],request) > OS_MAXSTR) {
        mdebug1("Request is too long.");
        os_free(command);
        OSHash_Delete_ex(request_hash,buffer);
        return -1;
    }

    /* Send request to external executable by socket */
    if(data->socket) {
        int sock;
retry:
        if (sock = external_socket_connect(data->socket, data->timeout), sock < 0) {
            if (!data->exec_path) {
                mdebug1("Could not connect to external socket. Is the process running?");
            } else {
                launch_socket(data->exec_path);
                goto retry;
            }
        } else {
            char msg[OS_SIZE_128] = {0};
            int msg_len = snprintf(msg, OS_SIZE_128,"%s:%s", exec_params[type], request);

            if( msg_len > OS_SIZE_128) {
                mdebug1("Request is too long for socket.");
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                return -1;
            }

            if (send(sock, msg, msg_len, 0) < 0) {
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                close(sock);
                return -1;
            }

            ssize_t length;
            os_calloc(OS_MAXSTR + 1,sizeof(char),output);
            if (length = recv(sock, output, OS_MAXSTR,0), length < 0) {
                mdebug1("No data received from external socket");
                os_free(output);
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                close(sock);
                return -1;
            } else if (length == 0) {
                os_free(output);
                os_free(command);
                OSHash_Delete_ex(request_hash,buffer);
                close(sock);
                return -1;
            } else {
                output[length] = '\0';
            }
            close(sock);
        }
    }
    /* Execute external program */
    else if (wm_exec(command, &output, &result_code, data->timeout, NULL) < 0) {

        if (result_code == EXECVE_ERROR) {
            mwarn("Cannot run key pulling integration (%s): path is invalid or file has no permissions.", data->exec_path);
        } else {
            mwarn("Error executing [%s]", data->exec_path);
        }

        os_free(command);
        OSHash_Delete_ex(request_hash,buffer);
        return -1;
    } else if (result_code != 0) {
        mwarn("Key pulling integration (%s) returned code %d.", data->exec_path, result_code);
    }

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
            mdebug1("Could not get a key from %s %s. Error: '%s'.", type == W_TYPE_ID ? "ID" : "IP",
                    request, error_message->valuestring && *error_message->valuestring != '\0' ? error_message->valuestring : "unknown");
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
            auth_add_agent(sock, id, agent_name->valuestring, agent_address->valuestring, agent_key->valuestring, data->force_insert, 1, agent_id->valuestring, 0);
            close(sock);
        }
        cJSON_Delete(agent_infoJSON);
    }
    os_free(output);

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

    if(data->exec_path){
        cJSON_AddStringToObject(wm_wd,"exec_path",data->exec_path);
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
            if(wm_key_request_dispatch(msg,data) < 0) {
                mdebug1("At w_request_thread(): Error getting external key");
            }
            os_free(msg);
        }
    }
}

static int external_socket_connect(char *socket_path, int repsonse_timeout) {
#ifndef WIN32
    int sock =  OS_ConnectUnixDomain(socket_path, SOCK_STREAM, OS_MAXSTR);
    OS_SetSendTimeout(sock, 5);
    OS_SetRecvTimeout(sock, repsonse_timeout, 0);
    return sock;
#else
    return -1;
#endif
}

void launch_socket(char *exec_path) {
    static pthread_mutex_t exec_path_mutex = PTHREAD_MUTEX_INITIALIZER;
    static time_t timestamp = 0;
    static wfd_t *wfd = NULL;
    time_t t_now;
    int sleep_time = 0;
    int result_code;

    w_mutex_lock(&exec_path_mutex);
    t_now = time(NULL);
    if (timestamp + RELAUNCH_TIME < t_now) {
        char **argv;
        mdebug1("Launching '%s'...", exec_path);

        if (wfd) {
            if ((kill(wfd->pid, 0) == -1) && (errno == ESRCH)) {
                // The process is dead
                result_code = WEXITSTATUS(wpclose(wfd));
                wfd = NULL;

                switch (result_code)
                {
                case 0:
                    break;
                case EXECVE_ERROR:
                    mwarn("Cannot run key pulling integration (%s): path is invalid or file has no permissions.", exec_path);
                    break;
                default:
                    mwarn("Key pulling integration (%s) returned code %d.", exec_path, result_code);
                }
            } else {
                mdebug1("The process which should have opened the socket is running. Rechecking within %d seconds.", RELAUNCH_TIME);
            }
        }
        if (!wfd) {
            if (argv = wm_strtok(exec_path), argv) {
                if(!(wfd = wpopenv(argv[0], argv, W_APPEND_POOL))) {
                    mwarn("Couldn not execute '%s'. Trying again in %d seconds.", exec_path, RELAUNCH_TIME);
                }
            }
        }

        timestamp = time(NULL);
    } else {
        if (wfd) {
            mdebug1("The executable was launched less than %d seconds ago. Trying to connect to the socket...", RELAUNCH_TIME);
            sleep(1);
        } else {
            sleep_time = timestamp + RELAUNCH_TIME - t_now;
        }
    }
    w_mutex_unlock(&exec_path_mutex);
    sleep(sleep_time);
}

#endif
