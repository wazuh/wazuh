/*
 * Wazuh Module - Configuration files checker
 * Copyright (C) 2015-2019, Wazuh Inc.
 * September, 2019
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef CLIENT
#if defined (__linux__) || defined (__MACH__)


#include "wm_check_config.h"
#include "check_config.h"
#define WARN_RESULT     "test was successful, however few errors have been found, please inspect your configuration file"


static void *wm_chk_conf_main();
static void wm_chk_conf_destroy();
cJSON *wm_chk_conf_dump(void);

const wm_context WM_CHK_CONF_CONTEXT = {
    "check_configuration",
    (wm_routine)wm_chk_conf_main,
    (wm_routine)wm_chk_conf_destroy,
    (cJSON * (*)(const void *))wm_chk_conf_dump
};

void *wm_chk_conf_main() {

    int sock, peer;
    char *buffer = NULL;
    ssize_t length;
    fd_set fdset;

    char *filetype = NULL;
    char *filepath = NULL;

    if (sock = OS_BindUnixDomain(CHK_CONF_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        mterror(WM_CHECK_CONFIG_LOGTAG, "Unable to bind to socket '%s': (%d) %s.", CHK_CONF_SOCK, errno, strerror(errno));
        return NULL;
    }

    mtinfo(WM_CHECK_CONFIG_LOGTAG, "Starting configuration checker thread.");
    while(1) {
        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);

        switch (select(sock + 1, &fdset, NULL, NULL, NULL)) {
            case -1:
                if (errno != EINTR) {
                    mterror_exit(WM_CHECK_CONFIG_LOGTAG, "At main(): select(): %s", strerror(errno));
                }
                continue;

            case 0:
                continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if (errno != EINTR) {
                mterror(WM_CHECK_CONFIG_LOGTAG, "At main(): accept(): %s", strerror(errno));
            }
            continue;
        }

        os_calloc(OS_MAXSTR+1, sizeof(char), buffer);
        length = OS_RecvUnix(peer, OS_MAXSTR, buffer);
        switch (length) {
            case -1:
                mterror(WM_CHECK_CONFIG_LOGTAG, "At main(): OS_RecvUnix(): %s", strerror(errno));
                break;

            case 0:
                mtinfo(WM_CHECK_CONFIG_LOGTAG, "Empty message from local client.");
                break;

            case OS_MAXLEN:
                mterror(WM_CHECK_CONFIG_LOGTAG, "Received message > %i", MAX_DYN_STR);
                break;

            default:
                if(check_event_rcvd(buffer, &filetype, &filepath) < 0) {
                    break;
                }

                if(!filepath) {
                    if(strcmp(filetype, "remote") == 0) {
                        filepath = strdup(DEFAULTDIR SHAREDCFG_DIR "/default/agent.conf");
                    } else {
                        filepath = strdup(DEFAULTCPATH);
                    }
                }

                char *output = NULL;
                int result = test_file(filetype, filepath, &output);

                cJSON *temp_obj = cJSON_CreateObject();

                if(output) {
                    char *aux = strtok(output, "\n");
                    char *aux_2 = NULL;        
                    int i;
                    int size = (int) strlen(aux);
                    cJSON *temp_obj2 = cJSON_CreateArray();
                    
                    if(result) {
                        cJSON_AddStringToObject(temp_obj, "error", "1");
                    } else {
                        cJSON_AddStringToObject(temp_obj, "error", "0");
                    }

                    while(aux){
                        cJSON *validator = cJSON_CreateObject();
                        aux_2 = strdup(aux);
                        if(strstr(aux, "WARNING")) {
                            cJSON_AddStringToObject(validator, "type", "WARNING");
                            for (i = 0; i <= size - 9; i++) {
                                aux_2[i] = aux_2[i + 9];
                            }
                            cJSON_AddStringToObject(validator, "message", aux_2);
                        } else if(strstr(aux, "INFO")) {
                            cJSON_AddStringToObject(validator, "type", "INFO");
                            for (i = 0; i <= size - 6; i++) {
                                aux_2[i] = aux_2[i + 6];
                            }
                            cJSON_AddStringToObject(validator, "message", aux_2);
                        } else if (result){
                            cJSON_AddStringToObject(validator, "type", "ERROR");
                            if (strstr(aux_2, "ERROR")) {
                                for (i = 0; i <= size - 7; i++) {
                                    aux_2[i] = aux_2[i + 7];
                                }
                            }
                            cJSON_AddStringToObject(validator, "message", aux_2);
                        }
                        cJSON_AddItemToArray(temp_obj2, validator);
                        aux = strtok(NULL, "\n");
                        if (aux) {
                            size = (int) strlen(aux);
                        }
                    }
                    cJSON_AddItemToObject(temp_obj, "data", temp_obj2);
                    os_free(output);
                    output = cJSON_PrintUnformatted(temp_obj);
                    os_free(aux);
                    os_free(aux_2);
                } else {	
                    cJSON_AddStringToObject(temp_obj, "error", "1");	
                    cJSON_AddStringToObject(temp_obj, "data", "failure testing the configuration file");	
                    output = cJSON_PrintUnformatted(temp_obj);	
                }

                mwarn("%s", output);

                /* Send the test result to API socket */
                /* send_message(output); */

                os_free(output);
                cJSON_Delete(temp_obj);

                break;
        }

        close(peer);
        os_free(filetype);
        os_free(filepath);
        os_free(buffer);
    }

    close(sock);
    return NULL;
}

void wm_chk_conf_destroy() {}

wmodule *wm_chk_conf_read(){
    wmodule * module;

    os_calloc(1, sizeof(wmodule), module);
    module->context = &WM_CHK_CONF_CONTEXT;
    module->tag = strdup(module->context->name);

    return module;
}

cJSON *wm_chk_conf_dump(void) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_wd = cJSON_CreateObject();
    cJSON_AddStringToObject(wm_wd, "enabled", "yes");
    cJSON_AddItemToObject(root, "check_configuration", wm_wd);
    return root;
}

int check_event_rcvd(const char *buffer, char **filetype, char **filepath) {
    const char *jsonErrPtr;
    cJSON *event = cJSON_ParseWithOpts(buffer, &jsonErrPtr, 0);

    if(!event) {
        merror("Cannot retrieve a JSON event from buffer");
        return -1;
    }

    cJSON *operation = cJSON_GetObjectItem(event, "operation");
    if(!operation) {
        merror("'operation' field not found");
        goto fail;
    } else if(strcmp(operation->valuestring, "GET")) {
        merror("Invalid operation: '%s', at received event.", operation->valuestring);
        goto fail;
    }

    cJSON *type = cJSON_GetObjectItem(event, "type");
    if(!type) {
        merror("'type' field not found");
        goto fail;
    } else if(strcmp(type->valuestring, "request")) {
        merror("Invalid operation type: '%s', at received event.", type->valuestring);
        goto fail;
    }

    cJSON *version = cJSON_GetObjectItem(event, "version");
    if(!version) {
        merror("'version' field not found");
        goto fail;
    }

    cJSON *component = cJSON_GetObjectItem(event, "component");
    if(!component) {
        merror("'component' field not found");
        goto fail;
    } else if(strcmp(component->valuestring, "check_configuration")) {
        merror("Unknown component: %s.", component->valuestring);
        goto fail;
    }

    /* Data values */
    cJSON *data = cJSON_GetObjectItem(event, "data");
    if(!data) {
        merror("'data' field not found");
        goto fail;
    }

    cJSON *data_type = cJSON_GetObjectItem(data, "type");
    if(!data_type) {
        merror("'data.type' item not found");
        goto fail;
    } else if(strcmp(data_type->valuestring, "manager") && strcmp(data_type->valuestring, "agent") && strcmp(data_type->valuestring, "remote")) {
        merror("Invalid value for data.type: %s", data_type->valuestring);
        goto fail;
    }
    *filetype = strdup(data_type->valuestring);

    cJSON *data_file = cJSON_GetObjectItem(data, "file");
    if(data_file) {
        *filepath = strdup(data_file->valuestring);
    } else {
        mwarn("'file' field not found, the default configuration file will be used.");
    }

    cJSON_Delete(event);
    return 0;

fail:
    cJSON_Delete(event);
    return -1;
}

int test_file(const char *filetype, const char *filepath, char **output) {

    int result_code;
    int result;
    int timeout = 2000; // Change timeout to an option 
    char *output_msg = NULL;
    char cmd[OS_SIZE_6144] = {0,};
    snprintf(cmd, OS_SIZE_6144, "%s/bin/check_configuration -t %s -f %s", DEFAULTDIR, filetype, filepath);

    if (wm_exec(cmd, &output_msg, &result_code, timeout, NULL) < 0) {
        if (result_code == EXECVE_ERROR) {
            wm_strcat(output, "WARNING: Path is invalid or file has insufficient permissions:", '\n');
        } else {
            wm_strcat(output, "WARNING: Error executing: ", '\n');
        }
        wm_strcat(output, cmd, '\n');
        os_free(output_msg);
        return OS_INVALID;
    }

    if (output_msg && *output_msg) {
        // Remove last newline
        size_t lastchar = strlen(output_msg) - 1;
        output_msg[lastchar] = output_msg[lastchar] == '\n' ? '\0' : output_msg[lastchar];

        wm_strcat(output, output_msg, '\n');
    }

    if(strcmp(filetype, "manager") == 0) {
        result = test_manager_conf(filepath, &output_msg);
    } else if(strcmp(filetype, "agent") == 0) {
        result = test_agent_conf(filepath, CAGENT_CGFILE, &output_msg);
    } else if(strcmp(filetype, "remote") == 0) {
        result = test_remote_conf(filepath, CRMOTE_CONFIG, &output_msg);
    } else {
        wm_strcat(output, "Unknown value for -t option.", '\n');
        return OS_INVALID;
    }

    os_free(output_msg);

    return result;
}

void send_message(const char *output) {

    /* Start api socket */
    int api_sock, rc;
    if ((api_sock = StartMQ(EXECQUEUEPATHAPI, WRITE)) < 0) {
        merror(QUEUE_ERROR, EXECQUEUEPATHAPI, strerror(errno));
        return;
    }

    if ((rc = OS_SendUnix(api_sock, output, 0)) < 0) {
        /* Error on the socket */
        if (rc == OS_SOCKTERR) {
            merror("socketerr (not available).");
            close(api_sock);
            return;
        }

        /* Unable to send. Socket busy */
        mdebug2("Socket busy, discarding message.");
    }

    close(api_sock);
    mdebug2("The message was sent successfully.");
}

#endif
#endif