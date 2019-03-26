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
static const char *XML_TAG = "tag";
static const char *XML_SOCKET_PATH = "socket_path";
static const char *XML_ADDRESS = "address";
static const char *XML_PORT = "port";
static const char *XML_SHARED_KEY = "shared_key";
static const char *XML_CA_FILE= "ca_file";
static const char *XML_USER = "user";
static const char *XML_PASSWORD = "password";

static short eval_bool(const char *str)
{
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

// Reading function
int wm_fluent_read(const OS_XML *xml,xml_node **nodes, wmodule *module)
{
    unsigned int i;
    wm_fluent_t *fluent;

    if(!module->data) {
        os_calloc(1, sizeof(wm_fluent_t), fluent);
        fluent->enabled = 1;
        fluent->tag = NULL;
        fluent->socket_path = NULL;
        fluent->address = "localhost";
        fluent->port = 24224;
        fluent->shared_key = NULL;
        fluent->ca_file = NULL;
        fluent->user = NULL;
        fluent->password = NULL;
        module->context = &WM_FLUENT_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = fluent;
    } 

    fluent = module->data;
    
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
            int enabled = eval_bool(nodes[i]->content);

            if(enabled == OS_INVALID){
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_FLUENT_CONTEXT.name);
                return OS_INVALID;
            }

            fluent->enabled = enabled;
        }
        else
        {
            mwarn("No such tag <%s> at module '%s'.", nodes[i]->element, WM_FLUENT_CONTEXT.name);
        }
    }

    // Validate parameters

    /* Tag is required */
    if (fluent->tag == NULL) {
        return OS_INVALID;
    }

    /* Socket path required */
    if (fluent->socket_path == NULL) {
        return OS_INVALID;
    }

    /* Password required if user is defined */
    if ( fluent->user && fluent->password == NULL ) {
        return OS_INVALID;
    }

    return 0;
}
