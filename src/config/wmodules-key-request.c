/* Copyright (C) 2015-2019, Wazuh Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "wazuh_modules/wmodules.h"
#include <stdio.h>

static const char *XML_ENABLED = "enabled";
static const char *XML_TIMEOUT= "timeout";
static const char *XML_THREADS = "threads";
static const char *XML_QUEUE_SIZE = "queue_size";
static const char *XML_EXEC_PATH = "exec_path";
static const char *XML_SOCKET = "socket";
static const char *XML_FORCE_INSERT = "force_insert";

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

// Reading function
int wm_key_request_read(xml_node **nodes, wmodule *module)
{
    unsigned int i;
    wm_krequest_t *key_request;

    os_calloc(1, sizeof(wm_krequest_t), key_request);
    key_request->enabled = 1;
    key_request->force_insert = 1;
    key_request->timeout = 60;
    key_request->threads = 1;
    key_request->queue_size = 1024;
    module->context = &WM_KEY_REQUEST_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = key_request;

    if (!nodes)
        return 0;

    for(i = 0; nodes[i]; i++)
    {
        if(!nodes[i]->element)
        {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        }
        else if (!strcmp(nodes[i]->element, XML_ENABLED))
        {
            if (key_request->enabled = eval_bool(nodes[i]->content), key_request->enabled == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_KEY_REQUEST_CONTEXT.name);
                return OS_INVALID;
            }
        }
        else if(!strcmp(nodes[i]->element, XML_EXEC_PATH))
        {
            if(key_request->exec_path) {
                free(key_request->exec_path);
            }

            if(strlen(nodes[i]->content) >= PATH_MAX) {
                merror("Exec path is too long at module '%s'. Max path length is %d", WM_KEY_REQUEST_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            }
            key_request->exec_path = strdup(nodes[i]->content);
        }
        else if(!strcmp(nodes[i]->element, XML_SOCKET))
        {
            if(key_request->socket) {
                free(key_request->socket);
            }

            if(strlen(nodes[i]->content) >= PATH_MAX) {
                merror("Socket path is too long at module '%s'. Max path length is %d", WM_KEY_REQUEST_CONTEXT.name,PATH_MAX);
                return OS_INVALID;
            }
            key_request->socket = strdup(nodes[i]->content);
        }
        else if(!strcmp(nodes[i]->element, XML_TIMEOUT))
        {
            key_request->timeout = strtoul(nodes[i]->content, NULL, 0);

            if (key_request->timeout < 1 || key_request->timeout >= UINT_MAX) {
                merror("Invalid interval at module '%s'", WM_KEY_REQUEST_CONTEXT.name);
                return OS_INVALID;
            }

            mdebug2("Timeout read: %d", key_request->timeout);
        }
        else if (!strcmp(nodes[i]->element, XML_THREADS))
        {
            key_request->threads = strtoul(nodes[i]->content, NULL, 0);

            if (key_request->threads < 1 || key_request->threads > 32) {
                merror("Invalid number of threads at module '%s'", WM_KEY_REQUEST_CONTEXT.name);
                return OS_INVALID;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_QUEUE_SIZE))
        {
            key_request->queue_size = strtoul(nodes[i]->content, NULL, 0);

            if (key_request->queue_size < 1 || key_request->queue_size > 220000) {
                merror("Invalid queue size at module '%s'", WM_KEY_REQUEST_CONTEXT.name);
                return OS_INVALID;
            }
        }
        else if (!strcmp(nodes[i]->element, XML_FORCE_INSERT))
        {
            if (key_request->force_insert = eval_bool(nodes[i]->content), key_request->force_insert == OS_INVALID)
            {
                merror("Invalid content for tag '%s' at module '%s'.", XML_FORCE_INSERT, WM_KEY_REQUEST_CONTEXT.name);
                return OS_INVALID;
            }
        }
        else
        {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_KEY_REQUEST_CONTEXT.name);
        }

    }
    return 0;
}
