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
int Read_Remote(XML_NODE node, void *d1, __attribute__((unused)) void *d2, char **output)
{
    int i = 0;
    int secure_count = 0;
    unsigned int pl = 0;
    unsigned int allow_size = 1;
    unsigned int deny_size = 1;
    remoted *logr;
    int defined_queue_size = 0;
    char message[OS_FLSIZE];

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
    const char * xml_queue_size = "queue_size";

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
                if (output == NULL) {
                    merror(DUP_SECURE);
                } else {
                    wm_strcat(output, "Can't add more than one secure connection.", '\n');
                }
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
        if (output == NULL) {
            merror_exit(MEM_ERROR, errno, strerror(errno));
        } else {
            snprintf(message, OS_FLSIZE + 1,
                "Could not acquire memory due to [(%d)-(%s)].",
                errno, strerror(errno));
            wm_strcat(output, message, '\n');
        }
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
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return (OS_INVALID);
        } else if (!node[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE + 1,
                    "Invalid NULL content for element: %s.",
                    node[i]->element);
                wm_strcat(output, message, '\n');
            }
            return (OS_INVALID);
        } else if (strcasecmp(node[i]->element, xml_remote_connection) == 0) {
            if (strcmp(node[i]->content, "syslog") == 0) {
                logr->conn[pl] = SYSLOG_CONN;
            } else if (strcmp(node[i]->content, "secure") == 0) {
                logr->conn[pl] = SECURE_CONN;
                if (++secure_count > 1) {
                    if (output == NULL) {
                        merror(DUP_SECURE);
                    } else {
                        wm_strcat(output, "Can't add more than one secure connection.", '\n');
                    }
                    return (OS_INVALID);
                }
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE + 1,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_port) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                if (output == NULL) {
                    merror(XML_VALUEERR, node[i]->element, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
            logr->port[pl] = atoi(node[i]->content);

            if (logr->port[pl] <= 0 || logr->port[pl] > 65535) {
                if (output == NULL) {
                    merror(PORT_ERROR, logr->port[pl]);
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Invalid port number: '%d'.",
                        logr->port[pl]);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_proto) == 0) {
            if (strcasecmp(node[i]->content, "tcp") == 0) {
#if defined(__linux__) || defined(__MACH__) || defined(__FreeBSD__) || defined(__OpenBSD__)
                logr->proto[pl] = IPPROTO_TCP;
#else
                if (output == NULL) {
                    merror(TCP_NOT_SUPPORT);
                } else {
                    wm_strcat(output, "TCP not supported for this operating system.", '\n');
                }
                return (OS_INVALID);
#endif
            } else if (strcasecmp(node[i]->content, "udp") == 0) {
                logr->proto[pl] = IPPROTO_UDP;
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element,
                       node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE + 1,
                    "Invalid value for element '%s': %s.",
                    node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_ipv6) == 0) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                logr->ipv6[pl] = 1;
            }
        } else if (strcasecmp(node[i]->element, xml_remote_lip) == 0) {
            os_strdup(node[i]->content, logr->lip[pl]);
            if (OS_IsValidIP(logr->lip[pl], NULL) != 1) {
                if (output == NULL) {
                    merror(INVALID_IP, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Invalid ip address: '%s'.",
                        node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_allowips) == 0) {
            allow_size++;
            logr->allowips = (os_ip **) realloc(logr->allowips, sizeof(os_ip *)*allow_size);
            if (!logr->allowips) {
                if (output == NULL) {
                    merror(MEM_ERROR, errno, strerror(errno));
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Could not acquire memory due to [(%d)-(%s)].",
                        errno, strerror(errno));
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }

            os_calloc(1, sizeof(os_ip), logr->allowips[allow_size - 2]);
            logr->allowips[allow_size - 1] = NULL;

            if (!OS_IsValidIP(node[i]->content, logr->allowips[allow_size - 2])) {
                if (output == NULL) {
                    merror(INVALID_IP, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Invalid ip address: '%s'.",
                        node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_denyips) == 0) {
            deny_size++;
            logr->denyips = (os_ip **) realloc(logr->denyips, sizeof(os_ip *)*deny_size);
            if (!logr->denyips) {
                if (output == NULL) {
                    merror(MEM_ERROR, errno, strerror(errno));
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Could not acquire memory due to [(%d)-(%s)].",
                        errno, strerror(errno));
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }

            os_calloc(1, sizeof(os_ip), logr->denyips[deny_size - 2]);
            logr->denyips[deny_size - 1] = NULL;
            if (!OS_IsValidIP(node[i]->content, logr->denyips[deny_size - 2])) {
                if (output == NULL) {
                    merror(INVALID_IP, node[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Invalid ip address: '%s'.",
                        node[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_queue_size) == 0) {
            char * end;

            logr->queue_size = strtol(node[i]->content, &end, 10);

            if (*end || logr->queue_size < 1) {
                if (output == NULL) {
                    merror("Invalid value for option '<%s>'", xml_queue_size);
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Invalid value for option '<%s>'",
                        xml_queue_size);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            if (*end) {
                if (output == NULL) {
                    merror("Invalid value for option '<%s>'", xml_queue_size);
                } else {
                    snprintf(message, OS_FLSIZE + 1,
                        "Invalid value for option '<%s>'",
                        xml_queue_size);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
            defined_queue_size = 1;
        } else if (output == NULL) {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        } else {
            snprintf(message, OS_FLSIZE + 1,
                "Invalid element in the configuration: '%s'.",
                node[i]->element);
            wm_strcat(output, message, '\n');
            return OS_INVALID;
        }
        i++;
    }

    /* conn must be set */
    if (logr->conn[pl] == 0) {
        if (output == NULL) {
            merror(CONN_ERROR);
        } else {
            wm_strcat(output, "No remote connection configured.", '\n');
        }
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
        if (output == NULL) {
            merror("Invalid option <%s> for Syslog remote connection.", xml_queue_size);
        } else {
            snprintf(message, OS_FLSIZE + 1,
                "Invalid option <%s> for Syslog remote connection.",
                xml_queue_size);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    return (0);
}

int Test_Remoted(const char *path, char **output) {
    remoted *test_remoted;
    os_calloc(1, sizeof(remoted), test_remoted);

    test_remoted->port = NULL;
    test_remoted->conn = NULL;
    test_remoted->allowips = NULL;
    test_remoted->denyips = NULL;
    test_remoted->nocmerged = 0;
    test_remoted->queue_size = 131072;

    if (ReadConfig(CREMOTE, path, test_remoted, NULL, output) < 0) {
        if (output == NULL){
            merror(CONF_READ_ERROR, "Remoted");
        } else {
            wm_strcat(output, "ERROR: Invalid configuration in Remoted", '\n');
        }
        free_remoted(test_remoted);
        return OS_INVALID;
	}

    if(test_remoted->queue_size < 1) {
        if (output == NULL){
            merror("Remoted Config: Queue size is invalid. Review configuration.");
        } else {
            wm_strcat(output, "Remoted Config: Queue size is invalid. Review configuration.", '\n');
        }
        free_remoted(test_remoted);
        return OS_INVALID;
    } else if(test_remoted->queue_size > 262144) {
        if (output == NULL){
            mwarn("Remoted Config: Queue size is very high. The application may run out of memory.");
        } else {
            wm_strcat(output, "Remoted Config: Queue size is very high. The application may run out of memory.", '\n');
        }
    }

    /* Frees the LogReader config struct */
    free_remoted(test_remoted);
    return 0;
}

void free_remoted(remoted * rmt) {
    if(rmt) {
        os_free(rmt->proto);
        os_free(rmt->port);
        os_free(rmt->conn);
        os_free(rmt->ipv6);
        os_free(rmt->lip);

        int i = 0;
        if(rmt->allowips) {
            while(rmt->allowips[i]) {
                os_free(rmt->allowips[i]);
                i++;
            }
        }
        os_free(rmt->allowips);

        i=0;
        if(rmt->denyips) {
            while(rmt->denyips[i]) {
                os_free(rmt->denyips[i]);
                i++;
            }
        }
        os_free(rmt->denyips);
        os_free(rmt);
    }
}
