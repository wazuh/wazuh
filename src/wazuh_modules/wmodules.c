/*
 * Wazuh Module Manager
 * Copyright (C) 2015-2020, Wazuh Inc.
 * April 27, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"
#include "os_crypto/md5/md5_op.h"
#include "os_crypto/sha1/sha1_op.h"
#include "os_crypto/sha256/sha256_op.h"

wmodule *wmodules = NULL;   // Config: linked list of all modules.
int wm_task_nice = 0;       // Nice value for tasks.
int wm_max_eps;             // Maximum events per second sent by OpenScap and CIS-CAT Wazuh Module
int wm_kill_timeout;        // Time for a process to quit before killing it
int wm_debug_level;

int FOREVER() {
    return 1;
}

// Read XML configuration and internal options

int wm_config() {

    int agent_cfg = 0;

    // Get defined values from internal_options

    wm_task_nice = getDefine_Int("wazuh_modules", "task_nice", -20, 19);
    wm_max_eps = getDefine_Int("wazuh_modules", "max_eps", 1, 1000);
    wm_kill_timeout = getDefine_Int("wazuh_modules", "kill_timeout", 0, 3600);

    // Read configuration: ossec.conf

    if (ReadConfig(CWMODULE, DEFAULTCPATH, &wmodules, &agent_cfg) < 0) {
        return -1;
    }

#ifdef CLIENT
    // Read configuration: agent.conf
    agent_cfg = 1;
    ReadConfig(CWMODULE | CAGENT_CONFIG, AGENTCONFIG, &wmodules, &agent_cfg);
#else
    wmodule *module;
    // The database module won't be available on agents

    if ((module = wm_database_read()))
        wm_add(module);

    // Downloading module

    if ((module = wm_download_read()))
        wm_add(module);

#endif

#if defined (__linux__) || (__MACH__) || defined (sun)
    wmodule * control_module;
    control_module = wm_control_read();
    wm_add(control_module);
#endif

    return 0;
}

// Add module to the global list

void wm_add(wmodule *module) {
    wmodule *current;

    if (wmodules) {
        for (current = wmodules; current->next; current = current->next);
        current->next = module;
    } else
        wmodules = module;
}

// Check general configuration

int wm_check() {
    wmodule *i = wmodules;
    wmodule *j;
    wmodule *next;
    wmodule *prev = wmodules;

    // Discard empty configurations

    while (i) {
        if (i->context) {
            prev = i;
            i = i->next;
        } else {
            next = i->next;
            free(i);

            if (i == wmodules) {
                wmodules = next;
            } else {
                prev->next = next;
            }

            i = next;
        }
    }

    // Check that a configuration exists

    if (!wmodules) {
        return -1;
    }

    // Get the last module of the same type

#ifndef __clang_analyzer__
    for (i = wmodules->next; i; i = i->next) {
        for (j = prev = wmodules; j != i; j = next) {
            next = j->next;

            if (i->tag && j->tag && !strcmp(i->tag, j->tag)) {

                mdebug1("Deleting repeated module '%s'.", j->tag);

                if (j == wmodules) {
                    wmodules = prev = next;
                } else {
                    prev->next = next;
                }
                wm_module_free(j);

            } else {
                prev = j;
            }
        }
    }
#endif

    return 0;
}

// Destroy configuration data

void wm_destroy() {
    wm_free(wmodules);
}

// Tokenize string separated by spaces, respecting double-quotes

char** wm_strtok(char *string) {
    char *c = string;
    char **output = (char**)calloc(2, sizeof(char*));
    size_t n = 1;

    if (!output)
        return NULL;

    *output = string;

    while ((c = strpbrk(c, " \"\\"))) {
        switch (*c) {
        case ' ':
            *(c++) = '\0';
            output[n++] = c;
            output = (char**)realloc(output, (n + 1) * sizeof(char*));
            if(!output){
                merror_exit(MEM_ERROR, errno, strerror(errno));
            }
            output[n] = NULL;
            break;

        case '\"':
            c++;

            while ((c = strpbrk(c, "\"\\"))) {
                if (*c == '\\')
                    c += 2;
                else
                    break;
            }

            if (!c) {
                free(output);
                return NULL;
            }

            c++;
            break;

        case '\\':
            c += 2;
        }
    }

    return output;
}

// Load or save the running state

int wm_state_io(const char * tag, int op, void *state, size_t size) {
    char path[PATH_MAX] = { '\0' };
    size_t nmemb;
    FILE *file;

    #ifdef WIN32
    snprintf(path, PATH_MAX, "%s\\%s", WM_DIR_WIN, tag);
    #else
    snprintf(path, PATH_MAX, "%s/%s", WM_STATE_DIR, tag);
    #endif

    if (!(file = fopen(path, op == WM_IO_WRITE ? "wb" : "rb"))) {
        return -1;
    }
    w_file_cloexec(file);

    nmemb = (op == WM_IO_WRITE) ? fwrite(state, size, 1, file) : fread(state, size, 1, file);
    fclose(file);

    return nmemb - 1;
}

long int wm_read_http_size(char *header) {
    long int size;
    char size_tag[] = "Content-Length:";
    char *found;
    char c_aux;

    if (found = strstr(header, size_tag), !found) {
        return 0;
    }
    found += strlen(size_tag);
    for (header = found; isdigit(*found) || *found == ' '; found++);

    c_aux = *found;
    *found = '\0';
    size = strtol(header, NULL, 10);
    *found = c_aux;
    return size;
}

void wm_free(wmodule * config) {
    wmodule *cur_module;
    wmodule *next_module;

    for (cur_module = config; cur_module; cur_module = next_module) {
        next_module = cur_module->next;

        wm_module_free(cur_module);
    }
}


void wm_module_free(wmodule * config){
    if (config->context && config->context->destroy)
            config->context->destroy(config->data);

    free(config->tag);
    free(config);
}


// Get read data
cJSON *getModulesConfig(void) {

    wmodule *cur_module;

    cJSON *root = cJSON_CreateObject();
    cJSON *wm_mod = cJSON_CreateArray();

    for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
        if (cur_module->context->dump) {
            cJSON * item = cur_module->context->dump(cur_module->data);

            if (item) {
                cJSON_AddItemToArray(wm_mod, item);
            }
        }
    }

    cJSON_AddItemToObject(root,"wmodules",wm_mod);

    return root;
}


cJSON *getModulesInternalOptions(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *internals = cJSON_CreateObject();

    cJSON_AddNumberToObject(internals,"wazuh_modules.task_nice",wm_task_nice);
    cJSON_AddNumberToObject(internals,"wazuh_modules.max_eps",wm_max_eps);
    cJSON_AddNumberToObject(internals,"wazuh_modules.kill_timeout",wm_kill_timeout);
    cJSON_AddNumberToObject(internals,"wazuh_modules.debug",wm_debug_level);

    cJSON_AddItemToObject(root,"internal_options",internals);

    return root;
}


// Send message to a queue waiting for a specific delay
int wm_sendmsg(int usec, int queue, const char *message, const char *locmsg, char loc) {

#ifdef WIN32
    int msec = usec / 1000;
    Sleep(msec);
#else
    struct timeval timeout = {0, usec};
    select(0, NULL, NULL, NULL, &timeout);
#endif

    if (SendMSG(queue, message, locmsg, loc) < 0) {
        merror("At wm_sendmsg(): Unable to send message to queue: (%s)", strerror(errno));
        return -1;
    }

    return 0;
}

// Check if a path is relative or absolute.
// Returns 0 if absolute, 1 if relative or -1 on error.
int wm_relative_path(const char * path) {

    if (!path || path[0] == '\0') {
        merror("At wm_relative_path(): Null path.");
        return -1;
    }

#ifdef WIN32
    if (((path[0] >= 'a' && path[0] <= 'z') || (path[0] >= 'A' && path[0] <= 'Z')) && path[1] == ':') {
        // Is a full path
        return 0;
    } else if ((path[0] == '\\' && path[1] == '\\')) {
        // Is a network resource
        return 0;
    } else {
        // Relative path
        return 1;
    }
#else
    if (path[0] != '/') {
        // Relative path
        return 1;
    }
#endif

    return 0;
}


// Get binary full path
int wm_get_path(const char *binary, char **validated_comm){

#ifdef WIN32
    const char sep[2] = ";";
#else
    const char sep[2] = ":";
#endif
    char *path;
    char *full_path;
    char *validated = NULL;
    char *env_path = NULL;
    char *save_ptr = NULL;

#ifdef WIN32
    if (IsFile(binary) == 0) {
#else
    if (binary[0] == '/') {
        // Check binary full path
        if (IsFile(binary) == -1) {
            return 0;
        }
#endif
        validated = strdup(binary);

    } else {

        env_path = getenv("PATH");
        path = strtok_r(env_path, sep, &save_ptr);

        while (path != NULL) {
            os_calloc(strlen(path) + strlen(binary) + 2, sizeof(char), full_path);
#ifdef WIN32
            snprintf(full_path, strlen(path) + strlen(binary) + 2, "%s\\%s", path, binary);
#else
            snprintf(full_path, strlen(path) + strlen(binary) + 2, "%s/%s", path, binary);
#endif
            if (IsFile(full_path) == 0) {
                validated = strdup(full_path);
                free(full_path);
                break;
            }
            free(full_path);
            path = strtok_r(NULL, sep, &save_ptr);
        }

        // Check binary found
        if (validated == NULL) {
            return 0;
        }
    }

    if (validated_comm) {
        *validated_comm = strdup(validated);
    }

    free(validated);
    return 1;
}


/**
 Check the binary wich executes a commad has the specified hash.
 Returns:
     1 if the binary matchs with the specified digest, 0 if not.
    -1 invalid parameters.
*/
int wm_validate_command(const char *command, const char *digest, crypto_type ctype) {

    os_md5 md5_binary;
    os_sha1 sha1_binary;
    os_sha256 sha256_binary;
    int match = 0;

    if (command == NULL || digest == NULL) {
        return -1;
    }

    switch (ctype) {

        case MD5SUM:
            // Get binary MD5
            OS_MD5_File(command, md5_binary, OS_BINARY);
            // Compare MD5 sums
            mdebug2("Comparing MD5 hash: '%s' | '%s'", md5_binary, digest);
            if (strcasecmp(md5_binary, digest) == 0) {
                match = 1;
            }
            break;

        case SHA1SUM:
            // Get binary SHA1
            OS_SHA1_File(command, sha1_binary, OS_BINARY);
            // Compare SHA1 sums
            mdebug2("Comparing SHA1 hash: '%s' | '%s'", sha1_binary, digest);
            if (strcasecmp(sha1_binary, digest) == 0) {
                match = 1;
            }
            break;

        case SHA256SUM:
            // Get binary SHA256
            OS_SHA256_File(command, sha256_binary, OS_BINARY);
            // Compare SHA256 sums
            mdebug2("Comparing SHA256 hash: '%s' | '%s'", sha256_binary, digest);
            if (strcasecmp(sha256_binary, digest) == 0) {
                match = 1;
            }
    }

    return match;
}

#ifdef __MACH__
void freegate(gateway *gate){
    if(!gate){
        return;
    }
    os_free(gate->addr);
    os_free(gate);
}
#endif
