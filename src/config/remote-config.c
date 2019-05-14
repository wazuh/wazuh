/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "remote-config.h"
#include "config.h"

/* Reads remote internal configuration */
void read_internal(remoted *logr, int nocmerged)
{
    if (getDefine_Int("remoted", "receive_chunk", 1024, 16384) != INT_OPT_NDEF)
        logr->receive_chunk = (unsigned)getDefine_Int("remoted", "receive_chunk", 1024, 16384);
    if (getDefine_Int("remoted", "buffer_relax", 0, 2) != INT_OPT_NDEF)
        logr->buffer_relax = getDefine_Int("remoted", "buffer_relax", 0, 2);
    if (getDefine_Int("remoted", "debug", 0, 2) != INT_OPT_NDEF)
        logr->logging = getDefine_Int("remoted", "debug", 0, 2);
    if (getDefine_Int("remoted", "pass_empty_keyfile", 0, 1) != INT_OPT_NDEF)
        logr->pass_empty_keyfile = getDefine_Int("remoted", "pass_empty_keyfile", 0, 1);
    if (getDefine_Int("remoted", "shared_reload", 1, 18000) != INT_OPT_NDEF)
        logr->shared_reload = getDefine_Int("remoted", "shared_reload", 1, 18000);
    if (getDefine_Int("remoted", "group_data_flush", 0, 2592000) != INT_OPT_NDEF)
        logr->group_data_flush = getDefine_Int("remoted", "group_data_flush", 0, 2592000);
    if (getDefine_Int("remoted", "merge_shared", 0, 1) != INT_OPT_NDEF)
        logr->nocmerged = nocmerged ? 1 : !getDefine_Int("remoted", "merge_shared", 0, 1);
    if (getDefine_Int("remoted", "recv_timeout", 1, 60) != INT_OPT_NDEF)
        logr->recv_timeout = getDefine_Int("remoted", "recv_timeout", 1, 60);
    if (getDefine_Int("remoted", "send_timeout", 1, 60) != INT_OPT_NDEF)
        logr->send_timeout = getDefine_Int("remoted", "send_timeout", 1, 60);
    if (getDefine_Int("remoted", "tcp_keepidle", 1, 7200) != INT_OPT_NDEF)
        logr->tcp_keepidle = getDefine_Int("remoted", "tcp_keepidle", 1, 7200);
    if (getDefine_Int("remoted", "tcp_keepintvl", 1, 100) != INT_OPT_NDEF)
        logr->tcp_keepintvl = getDefine_Int("remoted", "tcp_keepintvl", 1, 100);
    if (getDefine_Int("remoted", "tcp_keepcnt", 1, 50) != INT_OPT_NDEF)
        logr->tcp_keepcnt = getDefine_Int("remoted", "tcp_keepcnt", 1, 50);
    if (getDefine_Int("remoted", "rlimit_nofile", 1024, 1048576) != INT_OPT_NDEF)
        logr->rlimit_nofile = getDefine_Int("remoted", "rlimit_nofile", 1024, 1048576);
    if (getDefine_Int("remoted", "request_pool", 1, 4096) != INT_OPT_NDEF)
        logr->request_pool = getDefine_Int("remoted", "request_pool", 1, 4096);
    if (getDefine_Int("remoted", "request_timeout", 1, 600) != INT_OPT_NDEF)
        logr->request_timeout = getDefine_Int("remoted", "request_timeout", 1, 600);
    if (getDefine_Int("remoted", "response_timeout", 1, 3600) != INT_OPT_NDEF)
        logr->response_timeout = getDefine_Int("remoted", "response_timeout", 1, 3600);
    if (getDefine_Int("remoted", "request_rto_sec", 0, 60) != INT_OPT_NDEF)
        logr->request_rto_sec = getDefine_Int("remoted", "request_rto_sec", 0, 60);
    if (getDefine_Int("remoted", "request_rto_msec", 0, 999) != INT_OPT_NDEF)
        logr->request_rto_msec = getDefine_Int("remoted", "request_rto_msec", 0, 999);
    if (getDefine_Int("remoted", "max_attempts", 1, 16) != INT_OPT_NDEF)
        logr->max_attempts = getDefine_Int("remoted", "max_attempts", 1, 16);
    if (getDefine_Int("remoted", "guess_agent_group", 0, 1) != INT_OPT_NDEF)
        logr->guess_agent_group = getDefine_Int("remoted", "guess_agent_group", 0, 1);
    if (getDefine_Int("remoted", "sender_pool", 1, 64) != INT_OPT_NDEF)
        logr->sender_pool = getDefine_Int("remoted", "sender_pool", 1, 64);
    if (getDefine_Int("remoted", "worker_pool", 1, 16) != INT_OPT_NDEF)
        logr->worker_pool = getDefine_Int("remoted", "worker_pool", 1, 16);
    if (getDefine_Int("remoted", "keyupdate_interval", 1, 3600) != INT_OPT_NDEF)
        logr->keyupdate_interval = getDefine_Int("remoted", "keyupdate_interval", 1, 3600);
    if (getDefine_Int("remoted", "state_interval", 0, 86400) != INT_OPT_NDEF)
        logr->state_interval = getDefine_Int("remoted", "state_interval", 0, 86400);

}

/* Reads remote config */
int Read_Remote(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;
    int secure_count = 0;
    unsigned int pl = 0;
    unsigned int allow_size = 1;
    unsigned int deny_size = 1;
    remoted *logr;
    int defined_queue_size = 0;

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
    const char *xml_queue_size = "queue_size";

    /* Internal options */
    const char *xml_comp_avg_printout = "comp_avg_printout";
    const char *xml_recv_counter_flush = "recv_counter_flush";
    const char *xml_verify_msg_id = "verify_msg_id";
    const char *xml_pass_empty_keyfile = "pass_empty_keyfile";
    const char *xml_rlimit_nofile = "rlimit_nofile";
    const char *xml_logging = "logging";
    /* Pool block */
    const char *xml_pool = "pool";
    const char *xml_sender_pool = "sender";
    const char *xml_request_pool = "request";
    const char *xml_worker_pool = "worker";
    /* Timeout block */
    const char *xml_timeout = "timeout";
    const char *xml_max_attempts = "max_attempts";
    const char *xml_request_timeout = "request";
    const char *xml_response_timeout = "response";
    const char *xml_recv_timeout = "recv";
    const char *xml_send_timeout = "send";
    /* Request block */
    const char *xml_request = "request";
    const char *xml_request_rto_sec = "rto_sec";
    const char *xml_request_rto_msec = "rto_msec";
    /* Shared block */
    const char *xml_shared = "shared";
    const char *xml_shared_reload = "reload";
    const char *xml_merge_shared = "merge";
    /* Interval block */
    const char *xml_interval = "interval";
    const char *xml_keyupdate_interval = "keyupdate";
    const char *xml_state_interval = "state";
    /* Group block */
    const char *xml_group = "group";
    const char *xml_guess_agent_group = "guess_agent";
    const char *xml_group_data_flush = "data_flush";
    /* Memory block */
    const char *xml_memory = "memory";
    const char *xml_receive_chunk = "receive_chunk";
    const char *xml_buffer_relax = "buffer_relax";
    /* TCP */
    const char *xml_tcp = "tcp";
    const char *xml_tcp_keepidle = "keepidle";
    const char *xml_tcp_keepintvl = "keepintvl";
    const char *xml_tcp_keepcnt = "keepcnt";

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
            if (strcasecmp(node[i]->content, "tcp") == 0) {
#if defined(__linux__) || defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
                logr->proto[pl] = TCP_PROTO;
#else
                merror(TCP_NOT_SUPPORT);
                return (OS_INVALID);
#endif
            } else if (strcasecmp(node[i]->content, "udp") == 0) {
                logr->proto[pl] = UDP_PROTO;
            } else {
                merror(XML_VALUEERR, node[i]->element,
                       node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_ipv6) == 0) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                logr->ipv6[pl] = 1;
            }
        } else if (strcasecmp(node[i]->element, xml_remote_lip) == 0) {
            os_strdup(node[i]->content, logr->lip[pl]);
            if (OS_IsValidIP(logr->lip[pl], NULL) != 1) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
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
        } else if (strcmp(node[i]->element, xml_recv_counter_flush) == 0) {
            logr->recv_counter_flush = SetConf(node[i]->content, 10, 999999, 128, "client", xml_recv_counter_flush, 0, 0);
        } else if (strcmp(node[i]->element, xml_comp_avg_printout) == 0) {
            logr->comp_average_printout = SetConf(node[i]->content, 10, 999999, 19999, "client", xml_comp_avg_printout, 0, 0);
        } else if (strcmp(node[i]->element, xml_verify_msg_id) == 0) {
            logr->verify_msg_id = SetConf(node[i]->content, 0, 1, 0, "client", xml_verify_msg_id, 1, 1);
        } else if (strcmp(node[i]->element, xml_pass_empty_keyfile) == 0) {
            logr->pass_empty_keyfile = SetConf(node[i]->content, 0, 1, 1, "client", xml_pass_empty_keyfile, 1, 1);
        } else if (strcmp(node[i]->element, xml_pool) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_sender_pool)) {
                    logr->sender_pool = SetConf(children[j]->content, 1, 64, 8, "client", xml_sender_pool, 0, 0);
                } else if (!strcmp(children[j]->element, xml_request_pool)) {
                    logr->request_pool = SetConf(children[j]->content, 1, 4096, 1024, "client", xml_request_pool, 0, 0);
                } else if (!strcmp(children[j]->element, xml_worker_pool)) {
                    logr->worker_pool = SetConf(children[j]->content, 1, 16, 4, "client", xml_worker_pool, 0, 0);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
        } else if (strcmp(node[i]->element, xml_timeout) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_max_attempts)) {
                    logr->max_attempts = SetConf(children[j]->content, 1, 16, 4, "client", xml_max_attempts, 0, 0);
                } else if (!strcmp(children[j]->element, xml_request_timeout)) {
                    logr->request_timeout = SetConf(children[j]->content, 1, 600, 10, "client", xml_request_timeout, 0, 0);
                } else if (!strcmp(children[j]->element, xml_response_timeout)) {
                    logr->response_timeout = SetConf(children[j]->content, 1, 3600, 60, "client", xml_response_timeout, 0, 0);
                } else if (!strcmp(children[j]->element, xml_recv_timeout)) {
                    logr->recv_timeout = SetConf(children[j]->content, 1, 60, 1, "client", xml_recv_timeout, 0, 0);
                } else if (!strcmp(children[j]->element, xml_send_timeout)) {
                    logr->send_timeout = SetConf(children[j]->content, 1, 60, 1, "client", xml_send_timeout, 0, 0);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
        } else if (strcmp(node[i]->element, xml_rlimit_nofile) == 0) {
            logr->rlimit_nofile = SetConf(node[i]->content, 1024, 1048576, 65536, "client", xml_rlimit_nofile, 0, 0);
        } else if (strcmp(node[i]->element, xml_request) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_request_rto_sec)) {
                    logr->request_rto_sec = SetConf(children[j]->content, 0, 60, 1, "client", xml_request_rto_sec, 0, 0);
                } else if (!strcmp(children[j]->element, xml_request_rto_msec)) {
                    logr->request_rto_msec = SetConf(children[j]->content, 0, 999, 0, "client", xml_request_rto_msec, 0, 0);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
        } else if (strcmp(node[i]->element, xml_shared) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_merge_shared)) {
                    logr->nocmerged = SetConf(children[j]->content, 0, 1, 1, "client", xml_merge_shared, 1, 1);
                } else if (!strcmp(children[j]->element, xml_shared_reload)) {
                    logr->shared_reload = SetConf(children[j]->content, 1, 18000, 10, "client", xml_shared_reload, 0, 0);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
        } else if (strcmp(node[i]->element, xml_interval) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_state_interval)) {
                    logr->state_interval = SetConf(children[j]->content, 0, 86400, 5, "client", xml_state_interval, 1, 0);
                } else if (!strcmp(children[j]->element, xml_keyupdate_interval)) {
                    logr->keyupdate_interval = SetConf(children[j]->content, 1, 3600, 10, "client", xml_keyupdate_interval, 0, 0);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
        } else if (strcmp(node[i]->element, xml_group) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_guess_agent_group)) {
                    logr->guess_agent_group = SetConf(children[j]->content, 0, 1, 0, "client", xml_guess_agent_group, 1, 1);
                } else if (!strcmp(children[j]->element, xml_group_data_flush)) {
                    logr->group_data_flush = SetConf(children[j]->content, 0, 2592000, 86400, "client", xml_group_data_flush, 1, 0);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
        } else if (strcmp(node[i]->element, xml_memory) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_receive_chunk)) {
                    logr->receive_chunk = SetConf(children[j]->content, 1024, 16384, 4096, "client", xml_receive_chunk, 0, 0);
                } else if (!strcmp(children[j]->element, xml_buffer_relax)) {
                    logr->buffer_relax = SetConf(children[j]->content, 0, 2, 1, "client", xml_buffer_relax, 0, 0);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
        } else if (strcmp(node[i]->element, xml_tcp) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_tcp_keepidle)) {
                    logr->tcp_keepidle = SetConf(children[j]->content, 1, 7200, 30, "client", xml_tcp_keepidle, 0, 0);
                } else if (!strcmp(children[j]->element, xml_tcp_keepintvl)) {
                    logr->tcp_keepintvl = SetConf(children[j]->content, 1, 100, 10, "client", xml_tcp_keepintvl, 0, 0);
                } else if (!strcmp(children[j]->element, xml_tcp_keepcnt)) {
                    logr->tcp_keepcnt = SetConf(children[j]->content, 1, 50, 3, "client", xml_tcp_keepcnt, 0, 0);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
        } else if (strcmp(node[i]->element, xml_logging) == 0) {
            logr->logging = SetConf(node[i]->content, 0, 2, 0, "client", xml_logging, 0, 0);
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
        logr->proto[pl] = UDP_PROTO;
    }

    /* Queue_size is only for secure connections */
    if (logr->conn[pl] == SYSLOG_CONN && defined_queue_size) {
        merror("Invalid option <%s> for Syslog remote connection.", xml_queue_size);
        return OS_INVALID;
    }

    return (0);
}
