/*
 * Wazuh Module Manager
 * Copyright (C) 2016 Wazuh Inc.
 * April 27, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

wmodule *wmodules = NULL;   // Config: linked list of all modules.
int wm_task_nice = 0;       // Nice value for tasks.
int wm_max_eps;             // Maximum events per second sent by OpenScap and CIS-CAT Wazuh Module
int wm_kill_timeout;        // Time for a process to quit before killing it

// Read XML configuration and internal options

int wm_config() {

    int agent_cfg = 0;

    // Get defined values from internal_options

    wm_task_nice = getDefine_Int("wazuh_modules", "task_nice", -20, 19);
    wm_max_eps = getDefine_Int("wazuh_modules", "max_eps", 100, 1000);
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
    wmodule *database;
    // The database module won't be available on agents
    if ((database = wm_database_read()))
        wm_add(database);
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
    wmodule *prev;

    // Discard empty configurations

    while (i) {
        if (i->context) {
            i = i->next;
        } else {
            next = i->next;
            free(i);

            if (i == wmodules) {
                wmodules = next;
            }

            i = next;
        }
    }

    // Check that a configuration exists

    if (!wmodules) {
        return -1;
    }

    // Get the last module of the same type

    for (i = wmodules->next; i; i = i->next) {
        for (j = prev = wmodules; j != i; prev = j, j = next) {
            next = j->next;

            if (i->context->name == j->context->name) {
                mdebug1("Deleting repeated module '%s'.", j->context->name);

                if (j->context->destroy)
                    j->context->destroy(j->data);

                if (j == wmodules) {
                    wmodules = next;
                } else {
                    prev->next = next;
                }

                free(j);
            }
        }
    }

    return 0;
}

// Destroy configuration data

void wm_destroy() {
    wm_free(wmodules);
}

// Concatenate strings with optional separator

int wm_strcat(char **str1, const char *str2, char sep) {
    size_t len1;
    size_t len2;

    if (str2) {
        len2 = strlen(str2);

        if (*str1) {
            len1 = strlen(*str1);
            os_realloc(*str1, len1 + len2 + (sep ? 2 : 1), *str1);

            if (sep)
                memcpy(*str1 + (len1++), &sep, 1);
        } else {
            len1 = 0;
            os_malloc(len2 + 1, *str1);
        }

        memcpy(*str1 + len1, str2, len2 + 1);
        return 0;
    } else
        return -1;
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

    nmemb = (op == WM_IO_WRITE) ? fwrite(state, size, 1, file) : fread(state, size, 1, file);
    fclose(file);

    return nmemb - 1;
}

int wm_read_http_header(char *header) {
    int size;
    char *size_tag = "Content-Length:";
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
        if (cur_module->context && cur_module->context->destroy)
            cur_module->context->destroy(cur_module->data);
        free(cur_module);
    }
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
