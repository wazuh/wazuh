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
        switch (OS_RecvSecureTCP(peer, buffer, OS_MAXSTR)) {
            case OS_SOCKTERR:
                mterror(WM_CHECK_CONFIG_LOGTAG, "At main(): OS_RecvSecureTCP(): response size is bigger than expected");
                break;
            case -1:
                mterror(WM_CHECK_CONFIG_LOGTAG, "At main(): OS_RecvSecureTCP(): %s", strerror(errno));
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
                cJSON *json_output = cJSON_CreateObject();

                if(output) {
                    cJSON *data_array = cJSON_CreateArray();
                    char *json_data;
                    char *current_message;

                    if(result) {
                        cJSON_AddStringToObject(json_output, "error", "1");
                    } else {
                        cJSON_AddStringToObject(json_output, "error", "0");
                    }

                    for (current_message = strtok(output, "\n"); current_message; current_message = strtok(NULL, "\n")) {
                        char *output_data = NULL;
                        cJSON *validator = cJSON_CreateObject();

                        if(!strncmp(current_message, "WARNING", 7)) {
                            cJSON_AddStringToObject(validator, "type", "WARNING");
                            output_data = current_message + 9;
                        } else if(!strncmp(current_message, "INFO", 4)) {
                            cJSON_AddStringToObject(validator, "type", "INFO");
                            output_data = current_message + 6;
                        } else if (result){
                            cJSON_AddStringToObject(validator, "type", "ERROR");
                            if(!strncmp(current_message, "ERROR", 5)){
                                output_data = current_message + 7;
                            } else {
                                output_data = current_message;
                            }
                        } else {
                            output_data = current_message;
                        }

                        cJSON_AddStringToObject(validator, "message", output_data);
                        cJSON_AddItemToArray(data_array, validator);
                    }
                    cJSON_AddItemToObject(json_output, "data", data_array);

                    os_free(output);
                    output = strdup("ok");
                    json_data = cJSON_PrintUnformatted(json_output);
                    wm_strcat(&output, json_data, ' ');

                    os_free(json_data);
                } else {
                    cJSON_AddStringToObject(json_output, "error", "1");
                    cJSON_AddStringToObject(json_output, "data", "failure testing the configuration file");
                    output = strdup("ok");
                    wm_strcat(&output, cJSON_PrintUnformatted(json_output), ' ');
                }

                mwarn("%s", output);

                /* Send the test result to API socket */
                int rc;
                if ((rc = OS_SendSecureTCP(peer, strlen(output), output)) < 0) {
                    /* Error on the socket */
                    if (rc == OS_SOCKTERR) {
                        merror("socketerr (not available).");
                        break;
                    }

                    /* Unable to send. Socket busy */
                    mdebug2("Socket busy, discarding message.");
                }

                os_free(output);
                cJSON_Delete(json_output);

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
    int result;

    if(strcmp(filetype, "manager") == 0) {
        result = test_manager_conf(filepath, output);
    } else if(strcmp(filetype, "agent") == 0) {
        result = test_agent_conf(filepath, CAGENT_CGFILE, output);
    } else if(strcmp(filetype, "remote") == 0) {
        result = test_remote_conf(filepath, CRMOTE_CONFIG, output);
    } else {
        wm_strcat(output, "Unknown value for -t option.", '\n');
        return OS_INVALID;
    }

    if (result == 0) {
        wm_strcat(output, "Configuration validated successfully", '\n');
    }

    return result;
}

#endif
#endif