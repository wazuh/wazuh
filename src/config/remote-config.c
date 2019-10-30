/* Copyright (C) 2015-2019, Wazuh Inc.
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
    const char *xml_thread_stack_size = "thread_stack_size";

    const char *xml_recv_counter_flush = "recv_counter_flush";
    const char *xml_comp_average_printout = "comp_avg_printout";
    const char *xml_verify_msg_id = "verify_msg_id";
    const char *xml_pass_empty_keyfile = "pass_empty_keyfile";
    const char *xml_rlimit_nofile = "rlimit_nofile";
    const char *xml_log_level = "log_level";
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
    const char *xml_nocmerged = "merge";
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
    /* TCP block */
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
                logr->proto[pl] = IPPROTO_TCP;
#else
                merror(TCP_NOT_SUPPORT);
                return (OS_INVALID);
#endif
            } else if (strcasecmp(node[i]->content, "udp") == 0) {
                logr->proto[pl] = IPPROTO_UDP;
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
            SetConf(node[i]->content, &logr->recv_counter_flush, options.remote.recv_counter_flush, xml_recv_counter_flush);
        } else if (strcmp(node[i]->element, xml_comp_average_printout) == 0) {
            SetConf(node[i]->content, &logr->comp_average_printout, options.remote.comp_average_printout, xml_comp_average_printout);
        } else if (strcmp(node[i]->element, xml_verify_msg_id) == 0) {
            SetConf(node[i]->content, &logr->verify_msg_id, options.remote.verify_msg_id, xml_verify_msg_id);
        } else if (strcmp(node[i]->element, xml_pass_empty_keyfile) == 0) {
            SetConf(node[i]->content, &logr->pass_empty_keyfile, options.remote.pass_empty_keyfile, xml_pass_empty_keyfile);
        } else if (strcmp(node[i]->element, xml_pool) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_sender_pool)) {
                    SetConf(children[j]->content, &logr->sender_pool, options.remote.sender_pool, xml_sender_pool);
                } else if (!strcmp(children[j]->element, xml_request_pool)) {
                    SetConf(children[j]->content, &logr->request_pool, options.remote.request_pool, xml_request_pool);
                } else if (!strcmp(children[j]->element, xml_worker_pool)) {
                    SetConf(children[j]->content, &logr->worker_pool, options.remote.worker_pool, xml_worker_pool);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_timeout) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_max_attempts)) {
                    SetConf(children[j]->content, &logr->max_attempts, options.remote.max_attempts, xml_max_attempts);
                } else if (!strcmp(children[j]->element, xml_request_timeout)) {
                    SetConf(children[j]->content, &logr->request_timeout, options.remote.request_timeout, xml_request_timeout);
                } else if (!strcmp(children[j]->element, xml_response_timeout)) {
                    SetConf(children[j]->content, &logr->response_timeout, options.remote.response_timeout, xml_response_timeout);
                } else if (!strcmp(children[j]->element, xml_recv_timeout)) {
                    SetConf(children[j]->content, &logr->recv_timeout, options.remote.recv_timeout, xml_recv_timeout);
                } else if (!strcmp(children[j]->element, xml_send_timeout)) {
                    SetConf(children[j]->content, &logr->send_timeout, options.remote.send_timeout, xml_send_timeout);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_rlimit_nofile) == 0) {
            SetConf(node[i]->content, (int *) &logr->rlimit_nofile, options.remote.rlimit_nofile, xml_rlimit_nofile);
        } else if (strcmp(node[i]->element, xml_request) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_request_rto_sec)) {
                    SetConf(children[j]->content, &logr->request_rto_sec, options.remote.request_rto_sec, xml_request_rto_sec);
                } else if (!strcmp(children[j]->element, xml_request_rto_msec)) {
                    SetConf(children[j]->content, &logr->request_rto_msec, options.remote.request_rto_msec, xml_request_rto_msec);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_shared) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_nocmerged)) {
                    SetConf(children[j]->content, &logr->nocmerged, options.remote.nocmerged, xml_nocmerged);
                } else if (!strcmp(children[j]->element, xml_shared_reload)) {
                    SetConf(children[j]->content, &logr->shared_reload, options.remote.shared_reload, xml_shared_reload);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_interval) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_state_interval)) {
                    SetConf(children[j]->content, &logr->state_interval, options.remote.state_interval, xml_state_interval);
                } else if (!strcmp(children[j]->element, xml_keyupdate_interval)) {
                    SetConf(children[j]->content, &logr->keyupdate_interval, options.remote.keyupdate_interval, xml_keyupdate_interval);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_group) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_guess_agent_group)) {
                    SetConf(children[j]->content, &logr->guess_agent_group, options.remote.guess_agent_group, xml_guess_agent_group);
                } else if (!strcmp(children[j]->element, xml_group_data_flush)) {
                    SetConf(children[j]->content, &logr->group_data_flush, options.remote.group_data_flush, xml_group_data_flush);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_memory) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_receive_chunk)) {
                    SetConf(children[j]->content, (int *) &logr->receive_chunk, options.remote.receive_chunk, xml_receive_chunk);
                } else if (!strcmp(children[j]->element, xml_buffer_relax)) {
                    SetConf(children[j]->content, &logr->buffer_relax, options.remote.buffer_relax, xml_buffer_relax);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_tcp) == 0) {
            /* Get children */
            xml_node **children = NULL;
            if (children = OS_GetElementsbyNode(xml, node[i]), !children) {
                return OS_INVALID;
            }

            int j;
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, xml_tcp_keepidle)) {
                    SetConf(children[j]->content, &logr->tcp_keepidle, options.remote.tcp_keepidle, xml_tcp_keepidle);
                } else if (!strcmp(children[j]->element, xml_tcp_keepintvl)) {
                    SetConf(children[j]->content, &logr->tcp_keepintvl, options.remote.tcp_keepintvl, xml_tcp_keepintvl);
                } else if (!strcmp(children[j]->element, xml_tcp_keepcnt)) {
                    SetConf(children[j]->content, &logr->tcp_keepcnt, options.remote.tcp_keepcnt, xml_tcp_keepcnt);
                } else {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else if (strcmp(node[i]->element, xml_log_level) == 0) {
            SetConf(node[i]->content, &logr->log_level, options.remote.log_level, xml_log_level);
        } else if (strcmp(node[i]->element, xml_thread_stack_size) == 0) {
            SetConf(node[i]->content, &logr->thread_stack_size, options.global.thread_stack_size, xml_thread_stack_size);
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
        logr->proto[pl] = IPPROTO_UDP;
    }

    /* Queue_size is only for secure connections */
    if (logr->conn[pl] == SYSLOG_CONN && defined_queue_size) {
        merror("Invalid option <%s> for Syslog remote connection.", xml_queue_size);
        return OS_INVALID;
    }

    return (0);
}
