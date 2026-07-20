/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "os_net.h"
#include "global-config.h"
#include "config.h"
#include "string_op.h"

int Read_Global(__attribute__((unused)) const OS_XML *xml, XML_NODE node, void *configp, __attribute__((unused)) void *mailp)
{
    int i = 0;

    /* XML definitions */
    const char *xml_agents_disconnection_time = "agents_disconnection_time";
    const char *xml_agents_disconnection_alert_time = "agents_disconnection_alert_time";

    _Config *Config;
    Config = (_Config *)configp;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        }
        /* Agent's disconnection time parameter */
        if (strcmp(node[i]->element, xml_agents_disconnection_time) == 0) {
            if (Config) {
                long time = w_parse_time(node[i]->content);

                if (time < 1) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                } else {
                    Config->agents_disconnection_time = time;
                }
            }
        }
        /* Agent's disconnection alert time parameter */
        else if (strcmp(node[i]->element, xml_agents_disconnection_alert_time) == 0) {
            if (Config) {
                long time = w_parse_time(node[i]->content);

                if (time < 0) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                    return (OS_INVALID);
                } else {
                    Config->agents_disconnection_alert_time = time;
                }
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    return (0);
}
