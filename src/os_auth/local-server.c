/*
 * Local Authd server
 * Copyright (C) 2015, Wazuh Inc.
 * May 20, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <external/cJSON/cJSON.h>
#include <pthread.h>
#include <sys/wait.h>
#include "auth.h"
#include "os_err.h"
#include <config/authd-config.h>

typedef enum auth_local_err {
    EINTERNAL = 0,
    EJSON,
    ENOFUNCTION,
    ENOARGUMENT,
    ENONAME,
    ENOIP,
    EDUPIP,
    EDUPNAME,
    EKEY,
    ENOID,
    ENOAGENT,
    EDUPID,
    EAGLIM,
    EINVGROUP,
    ENOMASTER
} auth_local_err;


static const struct {
    int code;
    char *message;
} ERRORS[] = {
    { 9001, "Internal error" },
    { 9002, "Parsing JSON input" },
    { 9003, "No such function" },
    { 9004, "No such argument" },
    { 9005, "No such name" },
    { 9006, "No such IP" },
    { 9007, "Duplicate IP" },
    { 9008, "Duplicate name" },
    { 9009, "Issue generating key" },
    { 9010, "No such agent ID" },
    { 9011, "Agent ID not found" },
    { 9012, "Duplicate ID" },
    { 9013, "Maximum number of agents reached" },
    { 9014, "Invalid Group(s) Name(s)" },
    { 9015, "Cannot execute this request on a worker node" }
};

// Dispatch local request
static char* local_dispatch(const char *input);

// Remove an agent
static cJSON* local_remove(const char *id, int purge);

// Get agent data
static cJSON* local_get(const char *id);

// Generates an agent info json response
static cJSON* local_create_agent_response(const char *id, const char *name, const char *ip, const char *key);

// Generates an agent deleted response
static cJSON* local_create_agent_delete_response(void);

// Generates an error json response
static cJSON* local_create_error_response(int code, const char *message);

// Thread for internal server
void* run_local_server(__attribute__((unused)) void *arg) {
    int sock;
    int peer;
    char *buffer = NULL;
    char *response;
    ssize_t length;
    fd_set fdset;
    struct timeval timeout;

    authd_sigblock();

    mdebug1("Local server thread ready.");

    if (sock = OS_BindUnixDomain(AUTH_LOCAL_SOCK, SOCK_STREAM, OS_MAXSTR), sock < 0) {
        merror("Unable to bind to socket '%s': '%s'. Closing local server.", AUTH_LOCAL_SOCK, strerror(errno));
        return NULL;
    }

    while (running) {

        // Wait for socket
        FD_ZERO(&fdset);
        FD_SET(sock, &fdset);
        timeout.tv_sec = 1;
        timeout.tv_usec = 0;

        switch (select(sock + 1, &fdset, NULL, NULL, &timeout)) {
        case -1:
            if (errno != EINTR) {
                merror_exit("at run_local_server(): select(): %s", strerror(errno));
            }
            continue;
        case 0:
            continue;
        }

        if (peer = accept(sock, NULL, NULL), peer < 0) {
            if ((errno == EBADF && running) || (errno != EBADF && errno != EINTR)) {
                merror("at run_local_server(): accept(): %s", strerror(errno));
            }
            continue;
        }

        if (config.timeout_sec || config.timeout_usec) {
            if (OS_SetRecvTimeout(peer, config.timeout_sec, config.timeout_usec) < 0) {
                static int reported = 0;

                if (!reported) {
                    int error = errno;
                    merror("Could not set timeout to internal socket: %s (%d)", strerror(error), error);
                    reported = 1;
                }
            }
        }

        os_calloc(OS_MAXSTR, sizeof(char), buffer);
        switch (length = OS_RecvSecureTCP(peer, buffer,OS_MAXSTR), length) {
        case OS_SOCKTERR:
            merror("OS_RecvSecureTCP(): response size is bigger than expected");
            break;

        case -1:
            merror("OS_RecvSecureTCP(): %s", strerror(errno));
            break;

        case 0:
            mdebug2("Empty message from local client.");
            close(peer);
            break;

        case OS_MAXLEN:
            merror("Received message > %i", MAX_DYN_STR);
            close(peer);
            break;

        default:
            if (response = local_dispatch(buffer), response) {
                OS_SendSecureTCP(peer, strlen(response), response);
                free(response);
            }
        }

        close(peer);
        free(buffer);
    }

    mdebug1("Local server thread finished");

    close(sock);
    return NULL;
}

// Dispatch local request
char* local_dispatch(const char *input) {
    cJSON *request = NULL;
    cJSON *function;
    cJSON *arguments;
    cJSON *response = NULL;
    char *output = NULL;
    int ierror;
    char *groups = NULL;

    if (input[0] == '{') {
        if (config.worker_node) {
            ierror = ENOMASTER;
            goto fail;
        }

        const char *jsonErrPtr;
        if (request = cJSON_ParseWithOpts(input, &jsonErrPtr, 0), !request) {
            ierror = EJSON;
            goto fail;
        }

        if (function = cJSON_GetObjectItem(request, "function"), !function) {
            ierror = ENOFUNCTION;
            goto fail;
        }

        if (!strcmp(function->valuestring, "add")) {
            cJSON *item = NULL;
            cJSON *force = NULL;
            cJSON *disconnected_time = NULL;
            char *id = NULL;
            char *name = NULL;
            char *ip = NULL;
            char *key_hash = NULL;
            char *key = NULL;
            authd_force_options_t force_options = {0};

            if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
                ierror = ENOARGUMENT;
                goto fail;
            }

            id = (item = cJSON_GetObjectItem(arguments, "id"), item) ? item->valuestring : NULL;

            if (item = cJSON_GetObjectItem(arguments, "name"), !item) {
                ierror = ENONAME;
                goto fail;
            }
            name = item->valuestring;

            if (item = cJSON_GetObjectItem(arguments, "ip"), !item) {
                ierror = ENOIP;
                goto fail;
            }
            ip = item->valuestring;

            if (item = cJSON_GetObjectItem(arguments, "groups"), item) {
                groups = wstr_delete_repeated_groups(item->valuestring);
                if (!groups) {
                    ierror = EINVGROUP;
                    goto fail;
                }
            }

            key_hash = (item = cJSON_GetObjectItem(arguments, "key_hash"), item) ? item->valuestring : NULL;
            key = (item = cJSON_GetObjectItem(arguments, "key"), item) ? item->valuestring : NULL;

            if (force = cJSON_GetObjectItem(arguments, "force"), force) {
                if (item = cJSON_GetObjectItem(force, "enabled"), !item) {
                    ierror = EJSON;
                    goto fail;
                }
                force_options.enabled = (bool)item->valueint;

                if (item = cJSON_GetObjectItem(force, "key_mismatch"), !item) {
                    ierror = EJSON;
                    goto fail;
                }
                force_options.key_mismatch = (bool)item->valueint;

                if (disconnected_time = cJSON_GetObjectItem(force, "disconnected_time"), !disconnected_time) {
                    ierror = EJSON;
                    goto fail;
                }

                if (item = cJSON_GetObjectItem(disconnected_time, "enabled"), !item) {
                    ierror = EJSON;
                    goto fail;
                }
                force_options.disconnected_time_enabled = (bool)item->valueint;

                item = cJSON_GetObjectItem(disconnected_time, "value");
                if(cJSON_IsNumber(item)) {
                    force_options.disconnected_time = item->valueint;
                }
                else if (!cJSON_IsString(item) || get_time_interval(item->valuestring, &force_options.disconnected_time)) {
                    ierror = EJSON;
                    goto fail;
                }

                item = cJSON_GetObjectItem(force, "after_registration_time");
                if(cJSON_IsNumber(item)) {
                    force_options.after_registration_time = item->valueint;
                }
                else if (!cJSON_IsString(item) || get_time_interval(item->valuestring, &force_options.after_registration_time)) {
                    ierror = EJSON;
                    goto fail;
                }
            }

            response = local_add(id, name, ip, groups, key, key_hash, force ? &force_options : &config.force_options);

            os_free(groups);
        } else if (!strcmp(function->valuestring, "remove")) {
            cJSON *item;
            int purge;

            if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
                ierror = ENOARGUMENT;
                goto fail;
            }

            if (item = cJSON_GetObjectItem(arguments, "id"), !item) {
                ierror = ENOID;
                goto fail;
            }

            purge = cJSON_IsTrue(cJSON_GetObjectItem(arguments, "purge"));

            response = local_remove(item->valuestring, purge);
        } else if (!strcmp(function->valuestring, "get")) {
            cJSON *item;

            if (arguments = cJSON_GetObjectItem(request, "arguments"), !arguments) {
                ierror = ENOARGUMENT;
                goto fail;
            }

            if (item = cJSON_GetObjectItem(arguments, "id"), !item) {
                ierror = ENOID;
                goto fail;
            }

            response = local_get(item->valuestring);
        }

        if (!response) {
            merror("at local_dispatch(): response is null.");
            ierror = EINTERNAL;
            goto fail;
        }
        else {
            output = cJSON_PrintUnformatted(response);
            cJSON_Delete(response);
        }

        cJSON_Delete(request);
    } else {
        // Read configuration commands
        authcom_dispatch(input,&output);
    }

    return output;

fail:
    merror("ERROR %d: %s.", ERRORS[ierror].code, ERRORS[ierror].message);
    response = local_create_error_response(ERRORS[ierror].code, ERRORS[ierror].message);
    output = cJSON_PrintUnformatted(response);
    cJSON_Delete(response);
    cJSON_Delete(request);
    os_free(groups);
    return output;
}

cJSON* local_add(const char *id,
                 const char *name,
                 const char *ip,
                 const char *groups,
                 const char *key,
                 const char *key_hash,
                 authd_force_options_t *force_options) {
    int index;
    cJSON *response = NULL;
    int ierror;
    char* str_result = NULL;
    char _ip[IPSIZE + 1] = {0};

    mdebug2("add(%s)", name);
    w_mutex_lock(&mutex_keys);

    /* Check if groups are valid to be aggregated */
    if (groups) {
        if (OS_SUCCESS != w_auth_validate_groups(groups, NULL)) {
            ierror = EINVGROUP;
            goto fail;
        }
    }

    // Check for duplicate ID
    if (id && (index = OS_IsAllowedID(&keys, id), index >= 0)) {
        if(OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, force_options, &str_result)) {
            minfo("Duplicate ID. %s", str_result);
        } else {
            mwarn("Duplicate ID, rejecting enrollment. %s", str_result);
            ierror = EDUPID;
            goto fail;
        }
    }

    /* Check for duplicate IP */
    if (strcmp(ip, "any")) {
        os_ip *aux_ip;
        os_calloc(1, sizeof(os_ip), aux_ip);

        if (!OS_IsValidIP(ip, aux_ip)) {
            mwarn("Not valid IP '%s'", ip);
            w_free_os_ip(aux_ip);
            ierror = ENOIP;
            goto fail;
        }

        strncpy(_ip, aux_ip->ip, IPSIZE);
        w_free_os_ip(aux_ip);

        if (index = OS_IsAllowedIP(&keys, _ip), index >= 0) {
            if (OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, force_options, &str_result)) {
                minfo("Duplicate IP '%s'. %s", _ip, str_result);
            } else {
                mwarn("Duplicate IP '%s', rejecting enrollment. %s", _ip, str_result);
                ierror = EDUPIP;
                goto fail;
            }
        }
    } else {
        strncpy(_ip, ip, IPSIZE);
    }

    /* Check whether the agent name is the same as the manager */
    if (!strcmp(name, shost)) {
        ierror = EDUPNAME;
        goto fail;
    }

    /* Check for duplicate names */
    if (index = OS_IsAllowedName(&keys, name), index >= 0) {
        if(OS_SUCCESS == w_auth_replace_agent(keys.keyentries[index], key_hash, force_options, &str_result)) {
            minfo("Duplicate name. %s", str_result);
        } else {
            mwarn("Duplicate name '%s', rejecting enrollment. %s", name, str_result);
            ierror = EDUPNAME;
            goto fail;
        }
    }

    if (index = OS_AddNewAgent(&keys, id, name, _ip, key), index < 0) {
        ierror = EKEY;
        goto fail;
    }

    /* Add pending key to write */
    add_insert(keys.keyentries[index],groups);
    write_pending = 1;
    w_cond_signal(&cond_pending);

    response = local_create_agent_response(keys.keyentries[index]->id, name, _ip, keys.keyentries[index]->raw_key);
    w_mutex_unlock(&mutex_keys);

    minfo("Agent key generated for agent '%s' (requested locally)", name);
    os_free(str_result);
    return response;

fail:
    w_mutex_unlock(&mutex_keys);
    response = local_create_error_response(ERRORS[ierror].code, ERRORS[ierror].message);
    os_free(str_result);
    return response;
}

// Remove an agent
cJSON* local_remove(const char *id, int purge) {
    int index;
    cJSON *response = NULL;

    mdebug2("local_remove(id='%s', purge=%d)", id, purge);

    w_mutex_lock(&mutex_keys);

    if (index = OS_IsAllowedID(&keys, id), index < 0) {
        mdebug1("Error %d: %s.", ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
        response = local_create_error_response(ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
    } else {
        minfo("Agent '%s' (%s) deleted (requested locally)", id, keys.keyentries[index]->name);
        /* Add pending key to write */
        add_remove(keys.keyentries[index]);
        OS_DeleteKey(&keys, id, purge);
        write_pending = 1;
        w_cond_signal(&cond_pending);
        response = local_create_agent_delete_response();
    }

    w_mutex_unlock(&mutex_keys);
    return response;
}

// Get agent data
cJSON* local_get(const char *id) {
    int index;
    cJSON *response = NULL;

    mdebug2("local_get(%s)", id);
    w_mutex_lock(&mutex_keys);

    if (index = OS_IsAllowedID(&keys, id), index < 0) {
        mdebug1("Error %d: %s.", ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
        response = local_create_error_response(ERRORS[ENOAGENT].code, ERRORS[ENOAGENT].message);
    }
    else {
        response = local_create_agent_response(id, keys.keyentries[index]->name, keys.keyentries[index]->ip->ip, keys.keyentries[index]->raw_key);
    }

    w_mutex_unlock(&mutex_keys);
    return response;
}

// Generates an agent info json response
cJSON* local_create_agent_response(const char *id, const char *name, const char *ip, const char *key) {
    cJSON *response = NULL;
    cJSON *data = NULL;

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddItemToObject(response, "data", data = cJSON_CreateObject());
    cJSON_AddStringToObject(data, "id", id);
    cJSON_AddStringToObject(data, "name", name);
    cJSON_AddStringToObject(data, "ip", ip);
    cJSON_AddStringToObject(data, "key", key);

    return response;
}

// Generates an agent deleted response
static cJSON* local_create_agent_delete_response(void) {
    cJSON *response = NULL;

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", 0);
    cJSON_AddStringToObject(response, "data", "Agent deleted successfully.");

    return response;
}

// Generates an error json response
static cJSON* local_create_error_response(int code, const char *message) {
    cJSON *response = NULL;

    response = cJSON_CreateObject();
    cJSON_AddNumberToObject(response, "error", code);
    cJSON_AddStringToObject(response, "message", message);

    return response;
}
