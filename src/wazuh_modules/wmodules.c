/*
 * Wazuh Module Manager
 * Copyright (C) 2015, Wazuh Inc.
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
#include <sys/types.h>

wmodule *wmodules = NULL;   // Config: linked list of all modules.
int wm_task_nice = 0;       // Nice value for tasks.
static gid_t wm_gid;               // Group ID.
int wm_max_eps;             // Maximum events per second sent by CIS-CAT Wazuh Module
int wm_kill_timeout;        // Time for a process to quit before killing it
int wm_debug_level;


/**
 * List of modules that will be initialized by default
 * last position should be NULL
 * */
static const void *default_modules[] = {
    wm_agent_upgrade_read,
#ifndef CLIENT
    wm_task_manager_read,
#endif
    NULL
};

/**
 * Initializes the default wmodules (will be enabled even if the wodle section for that module)
 * is not defined
 * @param wmodules pointer to wmodules array structure
 * @return a status flag
 * @retval OS_SUCCESS if all reading methods are executed successfully
 * @retval OS_INVALID if there is an error
 * */
static int wm_initialize_default_modules(wmodule **wmodules);

// Read XML configuration and internal options

gid_t wm_getGroupID(void)
{
    return wm_gid;
}

void wm_setGroupID(const gid_t gid)
{
    wm_gid = gid;
}

int wm_config() {

    int agent_cfg = 0;

    // Get defined values from internal_options

    wm_task_nice = getDefine_Int("wazuh_modules", "task_nice", -20, 19);
    wm_max_eps = getDefine_Int("wazuh_modules", "max_eps", 1, 1000);
    wm_kill_timeout = getDefine_Int("wazuh_modules", "kill_timeout", 0, 3600);

    if(wm_initialize_default_modules(&wmodules) < 0) {
        return OS_INVALID;
    }


    // Read configuration: ossec.conf

    if (ReadConfig(CWMODULE, OSSECCONF, &wmodules, &agent_cfg) < 0) {
        return -1;
    }

#ifdef CLIENT
    // Read configuration: agent.conf
    agent_cfg = 1;
    ReadConfig(CWMODULE | CAGENT_CONFIG, AGENTCONFIG, &wmodules, &agent_cfg);
#else
    wmodule *module;

    if ((module = wm_router_read())) {
        wm_add(module);
    }

    if ((module = wm_content_manager_read())) {
        wm_add(module);
    }

    // The database module won't be available on agents
    if ((module = wm_database_read()))
        wm_add(module);

    // Downloading module
    if ((module = wm_download_read()))
        wm_add(module);

    // Inventory harvester
    if ((module = wm_inventory_harvester_read()))
        wm_add(module);

#endif

#if defined (__linux__) || (__MACH__) || defined (sun) || defined(FreeBSD) || defined(OpenBSD)
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

    if (!(file = wfopen(path, op == WM_IO_WRITE ? "wb" : "rb"))) {
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

char* wm_read_http_header_element(char *header, char *regex) {
    char *element = NULL;
    OSRegex os_regex;

    if (!header || !regex) {
        merror("Missing parameters.");
        return NULL;
    }

    if (!OSRegex_Compile(regex, &os_regex, OS_RETURN_SUBSTRING)) {
        mwarn("Cannot compile regex.");
        return NULL;
    }

    if (!OSRegex_Execute(header, &os_regex)) {
        mdebug1("No match regex.");
        OSRegex_FreePattern(&os_regex);
        return NULL;
    }

    if (!os_regex.d_sub_strings[0]) {
        mdebug1("No element was captured.");
        OSRegex_FreePattern(&os_regex);
        return NULL;
    }

    os_strdup(os_regex.d_sub_strings[0], element);

    OSRegex_FreePattern(&os_regex);
    return element;
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

// sync data
int modulesSync(char* args) {
    int ret = -1;
    wmodule *cur_module = NULL;
    int retry = 0;

    do {
        if (retry > 0) {
            usleep(retry * WM_MAX_WAIT);
            mdebug1("WModules is not ready. Retry %d", retry);
        }

        for (cur_module = wmodules; cur_module; cur_module = cur_module->next) {
            if (strstr(args, cur_module->context->name)) {
                ret = 0;
                if (strstr(args, "dbsync") && cur_module->context->sync != NULL) {
                    ret = cur_module->context->sync(args);
                }
                break;
            }
        }

        ++retry;

        if (retry > WM_MAX_ATTEMPTS) {
            break;
        }
    } while (ret != 0);

    if (ret) {
        merror("At modulesSync(): Unable to sync module '%s': (%d)", cur_module ? cur_module->tag : "",  ret);
    }
    return ret;
}

// Find a module

wmodule * wm_find_module(const char * name) {
    for (wmodule * module = wmodules; module != NULL; module = module->next) {
        if (strcmp(module->context->name, name) == 0) {
            return module;
        }
    }

    return NULL;
}

// Run a query in a module

size_t wm_module_query(char * query, char ** output) {
    char * module_name = query;
    char * args = strchr(query, ' ');

    if (args == NULL) {
        os_strdup("err {\"error\":1,\"message\":\"Module query needs arguments\"}", *output);
        return strlen(*output);
    }

    *args++ = '\0';

    wmodule * module = wm_find_module(module_name);
    if (module == NULL) {
        os_strdup("err {\"error\":2,\"message\":\"Module not found or not configured\"}", *output);
        return strlen(*output);
    }

    if (module->context->query == NULL) {
        os_strdup("err {\"error\":3,\"message\":\"This module does not support queries\"}", *output);
        return strlen(*output);
    }

    return module->context->query(module->data, args, output);
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

// Send message to a queue waiting for a specific delay
int wm_sendmsg_ex(int usec, int queue, const char *message, const char *locmsg, char loc, bool (*fn_prd)()) {

#ifdef WIN32
    int msec = usec / 1000;
    Sleep(msec);
#else
    struct timeval timeout = {0, usec};
    select(0, NULL, NULL, NULL, &timeout);
#endif

    if (SendMSGPredicated(queue, message, locmsg, loc, fn_prd) < 0) {
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

static int wm_initialize_default_modules(wmodule **wmodules) {
    wmodule *cur_wmodule = *wmodules;
    int i=0;
    while (default_modules[i]) {
        if(!cur_wmodule) {
            *wmodules = cur_wmodule = calloc(1, sizeof(wmodule));
        } else {
            os_calloc(1, sizeof(wmodule), cur_wmodule->next);
            cur_wmodule = cur_wmodule->next;
            if (!cur_wmodule) {
                merror(MEM_ERROR, errno, strerror(errno));
                return (OS_INVALID);
            }
        }
        // Point to read function
        int (*function_ptr)(const OS_XML *xml, xml_node **nodes, wmodule *module) = default_modules[i];

        if(function_ptr(NULL, NULL, cur_wmodule) == OS_INVALID) {
            return OS_INVALID;
        }
        i++;
    }
    return OS_SUCCESS;
}
