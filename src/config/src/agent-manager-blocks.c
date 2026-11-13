/* Copyright (C) Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "agent-manager-blocks.h"

/* How many children of `parent` are elements called `name`, or, with `nested`, how many
 * <manager> blocks those children hold. */
static int w_count_children(const OS_XML *xml, const xml_node *parent, const char *name, bool nested)
{
    xml_node **children = OS_GetElementsbyNode(xml, parent);
    int count = 0;

    for (int i = 0; children && children[i]; i++) {
        if (!children[i]->element || strcmp(children[i]->element, name) != 0) {
            continue;
        }

        count += nested ? w_count_children(xml, children[i], "manager", false) : 1;
    }

    OS_ClearNode(children);
    return count;
}

int w_count_agent_manager_blocks(const OS_XML *xml)
{
    xml_node **roots = OS_GetElementsbyNode(xml, NULL);
    int count = 0;

    for (int i = 0; roots && roots[i]; i++) {
        if (roots[i]->element && strcmp(roots[i]->element, WAZUHCONFIG) == 0) {
            count += w_count_children(xml, roots[i], "agent", true);
        }
    }

    OS_ClearNode(roots);
    return count;
}
