/*
 * Wazuh Module Configuration
 * Copyright (C) 2016 Wazuh Inc.
 * April 25, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_NAME = "name";

// Read wodle element

int Read_WModule(const OS_XML *xml, xml_node *node, void *d1, __attribute__((unused)) void *d2)
{
    wmodule **wmodules = (wmodule**)d1;
    wmodule *cur_wmodule;
    xml_node **children = NULL;

    if (!node->attributes[0]) {
        merror("%s: ERROR: No such attribute '%s' at module.", __local_name, XML_NAME);
        return OS_INVALID;
    }

    if (strcmp(node->attributes[0], XML_NAME)) {
        merror("%s: ERROR: Module attribute is not '%s'.", __local_name, XML_NAME);
        return OS_INVALID;
    }

    // Allocate memory

    if ((cur_wmodule = *wmodules)) {
        while (cur_wmodule->next)
            cur_wmodule = cur_wmodule->next;

        os_calloc(1, sizeof(wmodule), cur_wmodule->next);
        cur_wmodule = cur_wmodule->next;
    } else
        *wmodules = cur_wmodule = calloc(1, sizeof(wmodule));

    if (!cur_wmodule) {
        merror(MEM_ERROR, __local_name, errno, strerror(errno));
        return (OS_INVALID);
    }

    // Get children

    if (!(children = OS_GetElementsbyNode(xml, node))) {
        merror(XML_INVELEM, __local_name, node->element);
        return OS_INVALID;
    }

    // Select module by name

    if (!strcmp(node->values[0], WM_OSCAP_CONTEXT.name)){
        if (wm_oscap_read(xml, children, cur_wmodule) < 0) {
            OS_ClearNode(children);
            return OS_INVALID;
        }
    } else
        merror("%s: ERROR: Unknown module '%s'", __local_name, node->values[0]);

    OS_ClearNode(children);
    return 0;
}
