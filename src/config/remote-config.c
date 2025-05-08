/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "remote-config.h"
#include "config.h"

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

/**
 * @brief gets the remoted protocol configuration from a configuration string
 * @param content configuration string
 * @return returns the TCP/UDP protocol configuration
 */
STATIC int w_remoted_get_net_protocol(const char * content);

/**
 * @brief gets the remoted agents configuration
 *
 * @param node XML node
 * @param logr remoted configuration structure
 */
STATIC void w_remoted_parse_agents(XML_NODE node, remoted * logr);

/* Reads remote config */
int Read_Remote(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;
    int secure_count = 0;
    unsigned int pl = 0;
    unsigned int allow_size = 1;
    unsigned int deny_size = 1;
    remoted * logr = NULL;
    int defined_queue_size = 0;
    const int DEFAULT_RIDS_CLOSING_TIME = 300;

    /*** XML Definitions ***/

    /* Allowed and denied IPS */
    const char *xml_allowips = "allowed-ips";
    const char *xml_denyips = "denied-ips";

    /* Remote options */
    const char *xml_remote_port = "port";
    const char *xml_remote_proto = "protocol";
    const char *xml_remote_ipv6 = "ipv6";
    const char *xml_remote_connection = "connection";
    const char *xml_remote_lip = "local_ip";
    const char *xml_remote_agents = "agents";
    const char *xml_queue_size = "queue_size";
    const char *xml_rids_closing_time = "rids_closing_time";
    const char *xml_connection_overtake_time = "connection_overtake_time";
    const char *xml_allow_agents_enrollment = "allow_agents_enrollment";

    logr = (remoted *)d1;

    /* Getting allowed-ips */
    if (logr->allowips) {
        while (logr->allowips[allow_size - 1]) {
            allow_size++;
        }
    }

    /* Getting denied-ips */
    if (logr->denyips) {
        while (logr->denyips[deny_size - 1]) {
            deny_size++;
        }
    }

    /* conn and port must not be null */
    if (!logr->conn) {
        os_calloc(1, sizeof(int), logr->conn);
        logr->conn[0] = 0;
    }
    if (!logr->port) {
        os_calloc(1, sizeof(int), logr->port);
        logr->port[0] = 0;
    }
    if (!logr->proto) {
        os_calloc(1, sizeof(int), logr->proto);
        logr->proto[0] = 0;
    }
    if (!logr->ipv6) {
        os_calloc(1, sizeof(int), logr->ipv6);
        logr->ipv6[0] = 0;
    }
    if (!logr->lip) {
        os_calloc(1, sizeof(char *), logr->lip);
        logr->lip[0] = NULL;
    }

    /* Clean */
    while (logr->conn[pl] != 0) {
        if (logr->conn[pl] == SECURE_CONN) {
            if (++secure_count > 1) {
                merror(DUP_SECURE);
                return (OS_INVALID);
            }
        }
        pl++;
    }

    /* Add space for the last null connection/port */
    logr->port = (int *) realloc(logr->port, sizeof(int) * (pl + 2));
    logr->conn = (int *) realloc(logr->conn, sizeof(int) * (pl + 2));
    logr->proto = (int *) realloc(logr->proto, sizeof(int) * (pl + 2));
    logr->ipv6 = (int *) realloc(logr->ipv6, sizeof(int) * (pl + 2));
    logr->lip = (char **) realloc(logr->lip, sizeof(char *) * (pl + 2));
    if (!logr->port || !logr->conn || !logr->proto || !logr->ipv6 || !logr->lip) {
        merror_exit(MEM_ERROR, errno, strerror(errno));
    }

    logr->port[pl] = 0;
    logr->conn[pl] = 0;
    logr->proto[pl] = 0;
    logr->ipv6[pl] = 0;
    logr->lip[pl] = NULL;

    logr->port[pl + 1] = 0;
    logr->conn[pl + 1] = 0;
    logr->proto[pl + 1] = 0;
    logr->ipv6[pl + 1] = 0;
    logr->lip[pl + 1] = NULL;

    logr->rids_closing_time = DEFAULT_RIDS_CLOSING_TIME;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcasecmp(node[i]->element, xml_remote_connection) == 0) {
            if (strcmp(node[i]->content, "syslog") == 0) {
                logr->conn[pl] = SYSLOG_CONN;
            } else if (strcmp(node[i]->content, "secure") == 0) {
                logr->conn[pl] = SECURE_CONN;
                if (++secure_count > 1) {
                    merror(DUP_SECURE);
                    return (OS_INVALID);
                }
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_port) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->port[pl] = atoi(node[i]->content);

            if (logr->port[pl] <= 0 || logr->port[pl] > 65535) {
                merror(PORT_ERROR, logr->port[pl]);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_proto) == 0) {

            logr->proto[pl] = w_remoted_get_net_protocol(node[i]->content);

        } else if (strcasecmp(node[i]->element, xml_remote_ipv6) == 0) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                logr->ipv6[pl] = 1;
            } else if (strcasecmp(node[i]->content, "no") == 0) {
                logr->ipv6[pl] = 0;
            } else {
                mwarn(REMOTED_INV_VALUE_IGNORE, node[i]->content, xml_remote_ipv6);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_lip) == 0) {
            os_strdup(node[i]->content, logr->lip[pl]);
            if (OS_IsValidIP(logr->lip[pl], NULL) != 1) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            } else if (strchr(logr->lip[pl], ':') != NULL) {
                os_realloc(logr->lip[pl], IPSIZE + 1, logr->lip[pl]);
                OS_ExpandIPv6(logr->lip[pl], IPSIZE);
            }
        } else if (strcmp(node[i]->element, xml_allowips) == 0) {
            allow_size++;
            logr->allowips = (os_ip **) realloc(logr->allowips, sizeof(os_ip *)*allow_size);
            if (!logr->allowips) {
                merror(MEM_ERROR, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_calloc(1, sizeof(os_ip), logr->allowips[allow_size - 2]);
            logr->allowips[allow_size - 1] = NULL;

            if (!OS_IsValidIP(node[i]->content, logr->allowips[allow_size - 2])) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_denyips) == 0) {
            deny_size++;
            logr->denyips = (os_ip **) realloc(logr->denyips, sizeof(os_ip *)*deny_size);
            if (!logr->denyips) {
                merror(MEM_ERROR, errno, strerror(errno));
                return (OS_INVALID);
            }

            os_calloc(1, sizeof(os_ip), logr->denyips[deny_size - 2]);
            logr->denyips[deny_size - 1] = NULL;
            if (!OS_IsValidIP(node[i]->content, logr->denyips[deny_size - 2])) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_queue_size) == 0) {
            char * end;

            logr->queue_size = strtol(node[i]->content, &end, 10);

            if (*end || logr->queue_size < 1) {
                merror("Invalid value for option '<%s>'", xml_queue_size);
                return OS_INVALID;
            }

            if (*end) {
                merror("Invalid value for option '<%s>'", xml_queue_size);
                return OS_INVALID;
            }
            defined_queue_size = 1;
        } else if (strcmp(node[i]->element, xml_rids_closing_time) == 0) {
            char * time_unit_ptr = NULL;
            long rids_closing_time = 0;
            const char * TIME_UNITS = "sSmMhHdD";

            time_unit_ptr = strpbrk(node[i]->content, TIME_UNITS);
            rids_closing_time = w_parse_time(node[i]->content);

            if ((time_unit_ptr != NULL && *(time_unit_ptr + 1) !='\0') ||
                (rids_closing_time <= 0 || rids_closing_time > INT_MAX)) {
                    mwarn(REMOTED_INV_VALUE_DEFAULT, node[i]->content, xml_rids_closing_time);
                    rids_closing_time = REMOTED_RIDS_CLOSING_TIME_DEFAULT;
            }

            logr->rids_closing_time = (int) rids_closing_time;

        } else if (strcmp(node[i]->element, xml_connection_overtake_time) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                mwarn("Invalid value for element '%s':'%s'. Setting to default value: '%d'.", node[i]->element, node[i]->content, logr->connection_overtake_time);
            } else {
                int connection_overtake_time = atoi(node[i]->content);
                if (connection_overtake_time < 0 || connection_overtake_time > 3600) {
                    mwarn("Invalid value for element '%s':'%s'. Setting to default value: '%d'.", node[i]->element, node[i]->content, logr->connection_overtake_time);
                } else {
                    logr->connection_overtake_time = connection_overtake_time;
                }
            }
        } else if (strcmp(node[i]->element, xml_allow_agents_enrollment) == 0) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                logr->allow_agents_enrollment = true;
            } else if (strcasecmp(node[i]->content, "no") == 0) {
                logr->allow_agents_enrollment = false;
            } else {
                mwarn(REMOTED_INV_VALUE_IGNORE, node[i]->content, xml_allow_agents_enrollment);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_agents) == 0) {
            xml_node **children = OS_GetElementsbyNode(xml, node[i]);
            if (children == NULL) {
                continue;
            }

            w_remoted_parse_agents(children, logr);

            OS_ClearNode(children);

        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    /* conn must be set */
    if (logr->conn[pl] == 0) {
        merror(CONN_ERROR);
        return (OS_INVALID);
    }

    /* Set port in here */
    if (logr->port[pl] == 0) {
        if (logr->conn[pl] == SECURE_CONN) {
            logr->port[pl] = DEFAULT_SECURE;
        } else {
            logr->port[pl] = DEFAULT_SYSLOG;
        }
    }

    /* Set default protocol */
    if (logr->proto[pl] == 0) {
        logr->proto[pl] = REMOTED_NET_PROTOCOL_DEFAULT;
    }
    /* Only secure connections support TCP and UDP at the same time */
    else if (logr->conn[pl] != SECURE_CONN && (logr->proto[pl] == REMOTED_NET_PROTOCOL_TCP_UDP)) {
        mwarn(REMOTED_NET_PROTOCOL_ONLY_SECURE, REMOTED_NET_PROTOCOL_DEFAULT_STR);
        logr->proto[pl] = REMOTED_NET_PROTOCOL_DEFAULT;
    }

    /* Queue_size is only for secure connections */
    if (logr->conn[pl] == SYSLOG_CONN && defined_queue_size) {
        merror("Invalid option <%s> for Syslog remote connection.", xml_queue_size);
        return OS_INVALID;
    }

    return (0);
}

STATIC int w_remoted_get_net_protocol(const char * content) {

    const size_t MAX_ARRAY_SIZE = 64;
    const char * XML_REMOTE_PROTOCOL = "protocol";
    size_t current = 0;
    int retval = 0;

    char ** proto_arr = OS_StrBreak(',', content, MAX_ARRAY_SIZE);

    if (proto_arr) {
        while (proto_arr[current]) {
            char * word = &(proto_arr[current])[strspn(proto_arr[current], " ")];
            word[strcspn(word, " ")] = '\0';

            if (strcasecmp(word, REMOTED_NET_PROTOCOL_TCP_STR) == 0) {
                retval |= REMOTED_NET_PROTOCOL_TCP;
            } else if (strcasecmp(word, REMOTED_NET_PROTOCOL_UDP_STR) == 0) {
                retval |= REMOTED_NET_PROTOCOL_UDP;
            } else {
                mwarn(REMOTED_INV_VALUE_IGNORE, word, XML_REMOTE_PROTOCOL);
            }

            os_free(proto_arr[current]);
            current++;
        }

        os_free(proto_arr);

    }

    if (retval == 0) {
        mwarn(REMOTED_NET_PROTOCOL_ERROR, REMOTED_NET_PROTOCOL_DEFAULT_STR);
        retval = REMOTED_NET_PROTOCOL_DEFAULT;
    }

    return retval;
}

STATIC void w_remoted_parse_agents(XML_NODE node, remoted * logr) {
    const char * ALLOW_HIGHER_VERSIONS = "allow_higher_versions";

    int i = 0;
    while (node[i]) {
        if (strcasecmp(node[i]->element, ALLOW_HIGHER_VERSIONS) == 0) {
            if (strcmp(node[i]->content, "no") == 0) {
                logr->allow_higher_versions = false;
            }
            else if (strcmp(node[i]->content, "yes") == 0) {
                logr->allow_higher_versions = true;
            } else {
                mwarn(REMOTED_INV_VALUE_IGNORE, node[i]->content, ALLOW_HIGHER_VERSIONS);
            }
        }
        else {
            mwarn(XML_INVELEM, node[i]->element);
        }
        i++;
    }
}
