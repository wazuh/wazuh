/*
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/* Feeding XML fragments to the agent's <agent> and legacy <client> readers, shared by the
 * client configuration tests. */

#ifndef CLIENT_CONFIG_TEST_HELPERS_H
#define CLIENT_CONFIG_TEST_HELPERS_H

#include "shared.h"
#include "os_xml.h"
#include "client-config.h"
#include "config.h"

/* Parses `xml_str` and returns its top-level elements in `nodes`. */
static inline int parse_xml_block(const char *xml_str, OS_XML *xml, xml_node ***nodes) {
    if (OS_ReadXMLString(xml_str, xml) != 0) {
        return OS_INVALID;
    }

    return (*nodes = OS_GetElementsbyNode(xml, NULL)) ? 0 : OS_INVALID;
}

/* Parses `xml_str` as the body of a legacy 4.x <client>...</client> into cfg, which is not
 * reset, so it can run after another block was read into the same struct. */
static inline int parse_legacy_client(const char *xml_str, OS_XML *xml, xml_node ***nodes, agent *cfg) {
    if (parse_xml_block(xml_str, xml, nodes) != 0) {
        return OS_INVALID;
    }

    return Read_Legacy_Client(xml, *nodes, cfg, NULL);
}

/* Parses `xml_str` as the body of <agent>...</agent> into cfg, which is not reset. */
static inline int parse_agent_into(const char *xml_str, OS_XML *xml, xml_node ***nodes, agent *cfg) {
    if (parse_xml_block(xml_str, xml, nodes) != 0) {
        return OS_INVALID;
    }

    return Read_Agent(xml, *nodes, cfg, NULL);
}

static inline void clear_xml_block(OS_XML *xml, xml_node **nodes) {
    OS_ClearNode(nodes);
    OS_ClearXML(xml);
}

#endif /* CLIENT_CONFIG_TEST_HELPERS_H */
