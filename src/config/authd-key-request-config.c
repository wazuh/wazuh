/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#include "shared.h"
#include "authd-config.h"
#include "config.h"

static const char *XML_ENABLED = "enabled";
static const char *XML_TIMEOUT= "timeout";
static const char *XML_THREADS = "threads";
static const char *XML_QUEUE_SIZE = "queue_size";
static const char *XML_EXEC_PATH = "exec_path";
static const char *XML_SOCKET = "socket";
static const char *XML_FORCE_INSERT = "force_insert";
static const char *KREQUEST_NAME = "key-request";

static short eval_bool(const char *str) { return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID; }

// Reading function
int authd_read_key_request(xml_node **nodes, void *config) {
    authd_config_t *authd_config = (authd_config_t *)config;
    authd_key_request_t *key_request = &(authd_config->key_request);

    /*
    * Mechanism to avoid overwritting configuration settings when both 'key-request'
    * and 'agent-key-polling' configurations are present
    */
    if (key_request->compatibility_flag == 1) {
        return 0;
    }

    // Default configuration
    key_request->enabled = 1;
    key_request->timeout = 60;
    key_request->threads = 1;
    key_request->queue_size = 1024;

    if (!nodes) {
        return 0;
    }

    for (unsigned int i = 0; nodes[i]; i++) {
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        // Flag to enable or disable the module
        } else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            if (key_request->enabled = eval_bool(nodes[i]->content), key_request->enabled == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'", XML_ENABLED, KREQUEST_NAME);
                return OS_INVALID;
            }
        // Local path for script execution
        } else if (!strcmp(nodes[i]->element, XML_EXEC_PATH)) {
            os_free(key_request->exec_path);

            if (strlen(nodes[i]->content) >= PATH_MAX) {
                merror("Exec path is too long at module '%s'. Max path length is '%d'", KREQUEST_NAME, PATH_MAX);
                return OS_INVALID;
            } else if (*nodes[i]->content == '\0' || *nodes[i]->content == ' ') {
                merror("Invalid exec path at module '%s'", KREQUEST_NAME);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content, key_request->exec_path);
        // Socket path for script execution
        } else if (!strcmp(nodes[i]->element, XML_SOCKET)) {
            os_free(key_request->socket);

            if (strlen(nodes[i]->content) >= PATH_MAX) {
                merror("Socket path is too long at module '%s'. Max path length is '%d'", KREQUEST_NAME, PATH_MAX);
                return OS_INVALID;
            } else if (*nodes[i]->content == '\0' || *nodes[i]->content == ' ') {
                merror("Invalid socket path at module '%s'", KREQUEST_NAME);
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content, key_request->socket);
        // Timeout
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            key_request->timeout = atol(nodes[i]->content);

            if (key_request->timeout < 1 || key_request->timeout >= UINT_MAX) {
                merror("Invalid interval at module '%s'", KREQUEST_NAME);
                return OS_INVALID;
            }

            mdebug2("Timeout read: %d", key_request->timeout);
        // Maximum number of threads
        } else if (!strcmp(nodes[i]->element, XML_THREADS)) {
            key_request->threads = atol(nodes[i]->content);

            if (key_request->threads < 1 || key_request->threads > 32) {
                merror("Invalid number of threads at module '%s'", KREQUEST_NAME);
                return OS_INVALID;
            }
        // Queue size
        } else if (!strcmp(nodes[i]->element, XML_QUEUE_SIZE)) {
            key_request->queue_size = atol(nodes[i]->content);

            if (key_request->queue_size < 1 || key_request->queue_size > 220000) {
                merror("Invalid queue size at module '%s'", KREQUEST_NAME);
                return OS_INVALID;
            }
        // Deprecated "force-insert" function from older Agent Key Polling module
        } else if (!strcmp(nodes[i]->element, XML_FORCE_INSERT)) {
            mwarn("Deprecated option. This parameter is now inherited from Authd configuration.");
        } else {
            mwarn("No such tag <%s> at module '%s'", nodes[i]->element, KREQUEST_NAME);
        }
    }

    return 0;
}
