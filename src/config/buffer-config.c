/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "client-config.h"
#include "os_net/os_net.h"
#include "config.h"


int Read_ClientBuffer(XML_NODE node, __attribute__((unused)) void *d1, void *d2)
{
    int i = 0;

    /* XML definitions */
    const char *xml_buffer_disabled = "disabled";
    const char *xml_buffer_queue_size = "queue_size";
    const char *xml_events_per_second = "events_per_second";

    /* Old XML definition */
    const char *xml_buffer_length = "length";
    const char *xml_buffer_disable = "disable";

    if (!node)
        return 0;

    agent *logr;

    logr = (agent *)d2;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_buffer_disabled) == 0 || strcmp(node[i]->element, xml_buffer_disable) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                logr->buffer = 0;
            } else if (strcmp(node[i]->content, "no") == 0) {
                logr->buffer = 1;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_buffer_queue_size) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->buflength = atoi(node[i]->content);
            if (logr->buflength <= 0 || logr->buflength > 100000) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

        } else if (strcmp(node[i]->element, xml_buffer_length) == 0) {
            mwarn("The <%s> tag is deprecated for version newer than 2.1.1, please use <%s> instead.", xml_buffer_length, xml_buffer_queue_size);
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->buflength = atoi(node[i]->content);
            if (logr->buflength <= 0 || logr->buflength > 100000) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

        } else if (strcmp(node[i]->element, xml_events_per_second) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->events_persec = atoi(node[i]->content);
            if (logr->events_persec <= 0 || logr->events_persec > 1000) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    return (0);
}

int Test_ClientBuffer(const char * path){
    int fail = 0;
    agent test_clientBuffer = { .server = 0 };

    if (ReadConfig(CAGENT_CONFIG | CBUFFER, path, NULL, &test_clientBuffer) < 0) {
		merror(RCONFIG_ERROR,"ClientBuffer", path);
		fail = 1;
	}

    Free_Client(&test_clientBuffer);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}
