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
#include "client-config.h"
#include "os_net.h"
#include "config.h"
#include "sec.h"

int Read_Agent_Server(XML_NODE node, agent *logr);
int Read_Agent_SSL(XML_NODE node, agent *logr);
int Read_Agent_Batch(XML_NODE node, agent *logr);
int Read_Agent_Report(XML_NODE node, agent_report *report);
int Read_Agent_Enrollment(XML_NODE node, agent *logr);

/**
 * @brief Read the <agent> block, the 5.x name of what 4.x spelled <client> (#38103).
 *
 * The legacy name is not a second spelling of this block: an upgrade never rewrites
 * ossec.conf, so a file left by 4.x is read for one value only, by
 * Read_Legacy_Client_Address().
 */
int Read_Agent(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;
    char f_ip[128] = {'\0'};
    char * rip = NULL;

    /* XML definitions */
    const char *xml_agent_server = "server";
    const char *xml_agent_ssl = "ssl";
    const char *xml_agent_batch = "batch";
    const char *xml_agent_stats_report = "stats_report";
    const char *xml_agent_config_report = "config_report";
    const char *xml_local_ip = "local_ip";
    const char *xml_ar_disabled = "disable-active-response";
    const char *xml_notify_time = "notify_time";
    const char *xml_max_time_reconnect_try = "time-reconnect";
    const char *xml_main_ip_update_interval = "ip_update_interval";
    const char *xml_profile_name = "config-profile";
    const char *xml_auto_restart = "auto_restart";
    const char *xml_crypto_method = "crypto_method";
    const char *xml_agent_enrollment = "enrollment";

    /* Old XML definitions */
    const char *xml_agent_ip = "server-ip";
    const char *xml_agent_hostname = "server-hostname";
    const char *xml_protocol = "protocol";

    agent * logr = (agent *)d1;

    for (i = 0; node[i]; i++) {
        rip = NULL;
        XML_NODE chld_node = NULL;
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        }
        /* Get local IP */
        else if (strcmp(node[i]->element, xml_local_ip) == 0) {
            mwarn("The <%s> tag has no functionality, so it will have no effect.", xml_local_ip);
        }
        /* Get manager IP */
        else if (strcmp(node[i]->element, xml_agent_ip) == 0) {
            mwarn("The <%s> tag is deprecated, please use <server><address> instead.", xml_agent_ip);

            if (OS_IsValidIP(node[i]->content, NULL) != 1) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            }

            rip = node[i]->content;
        } else if (strcmp(node[i]->element, xml_agent_hostname) == 0) {
            mwarn("The <%s> tag is deprecated, please use <server><address> instead.", xml_agent_hostname);
            if (strchr(node[i]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s/", node[i]->content);
                rip = f_ip;
            } else {
                merror(AG_INV_HOST, node[i]->content);
                return (OS_INVALID);
            }

        }
        /* Get parameters for the configured server block */
        else if (strcmp(node[i]->element, xml_agent_server) == 0) {
            if (!(chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                merror(XML_INVELEM, node[i]->element);
                return (OS_INVALID);
            }
            if (Read_Agent_Server(chld_node, logr) < 0) {
                OS_ClearNode(chld_node);
                return (OS_INVALID);
            }
            OS_ClearNode(chld_node);
        } else if (strcmp(node[i]->element, xml_agent_ssl) == 0) {
            /* HTTPS transport TLS settings (sibling of <server>, #37702 §10). */
            if ((chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                if (Read_Agent_SSL(chld_node, logr) < 0) {
                    OS_ClearNode(chld_node);
                    return (OS_INVALID);
                }
                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, xml_agent_batch) == 0) {
            /* <batch><size>/<interval>: the /stateless send-rate model that
             * replaces the leaky bucket's pacing (#37835). */
            if ((chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                if (Read_Agent_Batch(chld_node, logr) < 0) {
                    OS_ClearNode(chld_node);
                    return (OS_INVALID);
                }
                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, xml_agent_stats_report) == 0) {
            /* <stats_report>/<config_report>: the two independent periodic
             * pushes to /stats and /config (#37843). <stats_report> stays off by
             * default; <config_report> ships on -- ClientConf() sets that default
             * before this parser runs, so it is invisible here. */
            if ((chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                if (Read_Agent_Report(chld_node, &logr->stats_report) < 0) {
                    OS_ClearNode(chld_node);
                    return (OS_INVALID);
                }
                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, xml_agent_config_report) == 0) {
            if ((chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                if (Read_Agent_Report(chld_node, &logr->config_report) < 0) {
                    OS_ClearNode(chld_node);
                    return (OS_INVALID);
                }
                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, xml_agent_enrollment) == 0) {
            if ((chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                if (Read_Agent_Enrollment(chld_node, logr) < 0) {
                    OS_ClearNode(chld_node);
                    return (OS_INVALID);
                }

                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, xml_notify_time) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->notify_time = atoi(node[i]->content);

            if (logr->notify_time < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_max_time_reconnect_try) == 0) {
            /* Deprecated with the HTTPS transport (#37702 restriction 4): no
             * persistent connection to reconnect. Accepted so upgraded configs
             * do not fail; it no longer has any effect. */
            mwarn("The <%s> option is deprecated and no longer has any effect.", xml_max_time_reconnect_try);
        } else if (strcmp(node[i]->element, "force_reconnect_interval") == 0) {
            mwarn("Deprecated option 'force_reconnect_interval' is not longer available.");
        } else if (strcmp(node[i]->element, xml_main_ip_update_interval) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->main_ip_update_interval = atoi(node[i]->content);
            if (logr->main_ip_update_interval < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_ar_disabled) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                logr->execdq = -1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                logr->execdq = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_profile_name) == 0) {
            /* Profile name can be anything hence no validation */
            os_strdup(node[i]->content, logr->profile);
        } else if (strcmp(node[i]->element, xml_auto_restart) == 0) {
            if (strcmp(node[i]->content, "yes") == 0) {
                logr->flags.auto_restart = 1;
            } else if (strcmp(node[i]->content, "no") == 0) {
                logr->flags.auto_restart = 0;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_protocol) == 0) {
            minfo("Ignoring the 'protocol' option. Switching to TCP.");
        } else if(strcmp(node[i]->element, xml_crypto_method) == 0){
            minfo("Ignoring the 'crypto_method' option. Switching to AES.");
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }

        // Add extra server (legacy configuration)
        if (rip) {
            os_realloc(logr->server, sizeof(agent_server) * (logr->server_count + 2), logr->server);
            os_strdup(rip, logr->server[logr->server_count].rip);
            logr->server[logr->server_count].port = 0;
            // Since these are new options we will only leave a default for legacy configurations
            logr->server[logr->server_count].max_retries = DEFAULT_MAX_RETRIES;
            logr->server[logr->server_count].retry_interval = DEFAULT_RETRY_INTERVAL;
            memset(logr->server + logr->server_count + 1, 0, sizeof(agent_server));
            logr->server_count++;
        }
    }

    // Assign the default port to legacy configurations

    for (i = 0; i < logr->server_count; ++i) {
        if (!logr->server[i].port) {
            logr->server[i].port = DEFAULT_HTTPS_REMOTE_PORT;
        }
    }
    return (0);
}

/**
 * @brief Read the one value still wanted from a 4.x <client> block: <server><address>.
 *
 * A WPK upgrade never rewrites ossec.conf, so a 5.x agent can start against a file that
 * only has <client> (#38103). The address is taken when <agent> did not already provide
 * one - so <agent> wins whichever block comes first - and everything else under <client>
 * is ignored rather than rejected, since the block is 4.x's and its options are not.
 *
 * Repeated addresses resolve the same way as under <agent>: the last one prevails
 */
int Read_Legacy_Client_Address(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    const char *xml_agent_server = "server";
    const char *xml_agent_addr = "address";
    char * address = NULL;

    agent * logr = (agent *)d1;

    if (logr->server) {
        return (0);
    }

    for (int i = 0; node[i]; i++) {
        XML_NODE chld_node = NULL;

        if (!node[i]->element || strcmp(node[i]->element, xml_agent_server) != 0) {
            continue;
        }

        if (!(chld_node = OS_GetElementsbyNode(xml, node[i]))) {
            continue;
        }

        for (int j = 0; chld_node[j]; j++) {
            if (!chld_node[j]->element || !chld_node[j]->content ||
                strcmp(chld_node[j]->element, xml_agent_addr) != 0) {
                continue;
            }

            os_free(address);
            os_strdup(chld_node[j]->content, address);
        }

        OS_ClearNode(chld_node);
    }

    if (!address) {
        return (0);
    }

    os_calloc(2, sizeof(agent_server), logr->server);
    logr->server[0].rip = address;
    if (strchr(logr->server[0].rip, ':') != NULL) {
        os_realloc(logr->server[0].rip, IPSIZE + 1, logr->server[0].rip);
        OS_ExpandIPv6(logr->server[0].rip, IPSIZE);
    }
    logr->server[0].port = DEFAULT_HTTPS_REMOTE_PORT;
    logr->server_count = 1;

    minfo("<agent><server><address> is not configured. Using <client><server><address> '%s' "
          "with the default port %d.", logr->server[0].rip, DEFAULT_HTTPS_REMOTE_PORT);

    return (0);
}

int Read_Agent_Shared(const OS_XML *xml, XML_NODE node, void *d1)
{
    /* XML definitions - what a manager may set through the centralized
     * configuration. Everything else in <agent> stays local to the endpoint. */
    const char *xml_agent_batch = "batch";

    agent * logr = (agent *)d1;
    int i = 0;

    for (i = 0; node[i]; i++) {
        XML_NODE chld_node = NULL;

        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_agent_batch) == 0) {
            /* How much traffic an agent is allowed to push at the manager is a
             * fleet-wide call, not a per-endpoint one, so <batch> is pushed the
             * same way the module configurations already are (#38163). */
            if ((chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                if (Read_Agent_Batch(chld_node, logr) < 0) {
                    OS_ClearNode(chld_node);
                    return (OS_INVALID);
                }

                OS_ClearNode(chld_node);
            }
        } else if (strcmp(node[i]->element, "force_reconnect_interval") == 0) {
            mwarn("Deprecated option 'force_reconnect_interval' is not longer available.");
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
    }

    return (0);
}

/**
 * @brief Read the <agent><server> block: the single manager endpoint.
 *
 * @param node Children of the <server> element.
 * @param logr Agent configuration to fill.
 * @return 0 on success, OS_INVALID on error.
 */
int Read_Agent_Server(XML_NODE node, agent * logr)
{
    /* XML definitions */
    const char *xml_agent_addr = "address";
    const char *xml_agent_port = "port";
    const char *xml_interface = "interface_index";
    const char *xml_protocol = "protocol";
    const char *xml_max_retries = "max_retries";
    const char *xml_retry_interval = "retry_interval";

    int j;
    char f_ip[128];
    char * rip = NULL;
    /* Default values */
    uint32_t network_interface = 0;
    int port = DEFAULT_HTTPS_REMOTE_PORT;
    bool port_set = false;
    int max_retries = DEFAULT_MAX_RETRIES;
    int retry_interval = DEFAULT_RETRY_INTERVAL;

    /* Get parameters for each configurated server*/

    for (j = 0; node[j]; j++) {
        if (!node[j]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[j]->content) {
            merror(XML_VALUENULL, node[j]->element);
            return (OS_INVALID);
        }
        /* Get server address (IP or hostname) */
        else if (strcmp(node[j]->element, xml_agent_addr) == 0) {
            if (OS_IsValidIP(node[j]->content, NULL) == 1) {
                rip = node[j]->content;
            } else if (strchr(node[j]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s", node[j]->content);
                rip = f_ip;
            } else {
                merror(AG_INV_HOST, node[j]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_agent_port) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }

            if (port = atoi(node[j]->content), port <= 0 || port > 65535) {
                merror(PORT_ERROR, port);
                return (OS_INVALID);
            }

            port_set = true;
        } else if (strcmp(node[j]->element, xml_interface) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
            int interface_numeric = atoi(node[j]->content);
            if (interface_numeric <= 0) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
            network_interface = (uint32_t)interface_numeric;
        } else if (strcmp(node[j]->element, xml_protocol) == 0) {
            minfo("Ignoring the 'protocol' option. Switching to TCP.");
        } else if (strcmp(node[j]->element, xml_max_retries) == 0 ||
                   strcmp(node[j]->element, xml_retry_interval) == 0) {
            /* Deprecated with the HTTPS transport (#37702 restriction 4): server
             * rotation and the connection-retry loop are removed. Accepted so
             * upgraded configs do not fail; no longer has any effect. */
            mwarn("The <%s> option is deprecated and no longer has any effect.", node[j]->element);
        } else {
            merror(XML_INVELEM, node[j]->element);
            return (OS_INVALID);
        }
    }

    if (!rip) {
        merror("No such address in the configuration.");
        return (OS_INVALID);
    }

    /* Single <server> block: the last one prevails (#37702 restriction 2) and
     * server rotation is removed (restriction 3), so replace any previous entry
     * instead of appending. The array keeps a NULL-rip sentinel at index 1. */
    if (logr->server) {
        if (logr->server_count > 0) {
            mwarn("Only one <server> block is supported; the last one prevails.");
        }
        for (int k = 0; logr->server[k].rip; k++) {
            os_free(logr->server[k].rip);
        }
        os_free(logr->server);
        logr->server = NULL;
        logr->server_count = 0;
    }

    os_calloc(2, sizeof(agent_server), logr->server);
    os_strdup(rip, logr->server[0].rip);
    if (strchr(logr->server[0].rip, ':') != NULL) {
        os_realloc(logr->server[0].rip, IPSIZE + 1, logr->server[0].rip);
        OS_ExpandIPv6(logr->server[0].rip, IPSIZE);
    }
    logr->server[0].network_interface = network_interface;
    logr->server[0].port = port;
    logr->server[0].max_retries = max_retries;
    logr->server[0].retry_interval = retry_interval;
    logr->server_count = 1;

    if (!port_set) {
        minfo("<agent><server><port> is not configured. Using the default port %d.",
              DEFAULT_HTTPS_REMOTE_PORT);
    }

    return (0);
}

/* TLS 1.3 ciphersuite names, RFC 8446 section B.4. These are what OpenSSL's
 * SSL_CTX_set_ciphersuites() takes, which is what the agent's <ciphers> ends up
 * feeding through libcurl's CURLOPT_TLS13_CIPHERS. */
static const char *VALID_TLS13_CIPHERSUITES[] = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
    NULL
};

static bool is_tls13_ciphersuite(const char *name, size_t length)
{
    for (int i = 0; VALID_TLS13_CIPHERSUITES[i]; i++) {
        if (strlen(VALID_TLS13_CIPHERSUITES[i]) == length &&
            strncmp(name, VALID_TLS13_CIPHERSUITES[i], length) == 0) {
            return true;
        }
    }

    return false;
}

/**
 * @brief Validate a colon-separated TLS 1.3 ciphersuite list.
 *
 * The agent negotiates nothing below TLS 1.3, so a TLS 1.2 name here would parse
 * and then never constrain a session — silently, since OpenSSL is never told
 * about it. Rejecting at parse time is the difference between a startup error
 * and a security option that quietly does nothing.
 *
 * @param ciphers Raw <ciphers> content.
 * @return 0 when every element is a known suite, OS_INVALID otherwise.
 */
static int w_client_validate_tls13_ciphers(const char *ciphers)
{
    const char *element = ciphers;

    if (!ciphers || !*ciphers) {
        merror("Invalid 'ciphers' option: expected TLS 1.3 cipher suite names.");
        return OS_INVALID;
    }

    /* Walked by hand rather than with strtok_r, which collapses runs of
     * separators: under it ':X', 'X::' and 'X::Y' all pass while naming a suite
     * that is not there. Every element between two separators is checked,
     * including an empty first or last one. */
    for (;;) {
        const char *separator = strchr(element, ':');
        const size_t length = separator ? (size_t)(separator - element) : strlen(element);

        if (length == 0) {
            merror("Invalid 'ciphers' option: '%s' has an empty cipher suite name.", ciphers);
            return OS_INVALID;
        }

        if (!is_tls13_ciphersuite(element, length)) {
            merror("Invalid TLS 1.3 cipher suite '%.*s' in the 'ciphers' option.", (int)length, element);
            return OS_INVALID;
        }

        if (!separator) {
            return 0;
        }

        element = separator + 1;
    }
}

int Read_Agent_SSL(XML_NODE node, agent * logr)
{
    /* XML definitions — the <agent><ssl> transport block (#37702 §10). */
    const char *xml_certificate = "certificate";
    const char *xml_key = "key";
    const char *xml_certificate_authorities = "certificate_authorities";
    const char *xml_verification_mode = "verification_mode";
    const char *xml_ciphers = "ciphers";

    for (int j = 0; node[j]; j++) {
        if (!node[j]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[j]->content) {
            merror(XML_VALUENULL, node[j]->element);
            return (OS_INVALID);
        } else if (strcmp(node[j]->element, xml_certificate) == 0) {
            os_free(logr->ssl.certificate);
            os_strdup(node[j]->content, logr->ssl.certificate);
        } else if (strcmp(node[j]->element, xml_key) == 0) {
            os_free(logr->ssl.key);
            os_strdup(node[j]->content, logr->ssl.key);
        } else if (strcmp(node[j]->element, xml_certificate_authorities) == 0) {
            os_free(logr->ssl.certificate_authorities);
            os_strdup(node[j]->content, logr->ssl.certificate_authorities);
        } else if (strcmp(node[j]->element, xml_verification_mode) == 0) {
            if (strcmp(node[j]->content, "full") == 0) {
                logr->ssl.verification_mode = AGENT_VERIFY_FULL;
            } else if (strcmp(node[j]->content, "certificate") == 0) {
                logr->ssl.verification_mode = AGENT_VERIFY_CERT;
            } else if (strcmp(node[j]->content, "none") == 0) {
                logr->ssl.verification_mode = AGENT_VERIFY_NONE;
            } else {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_ciphers) == 0) {
            if (w_client_validate_tls13_ciphers(node[j]->content) == OS_INVALID) {
                return (OS_INVALID);
            }
            os_free(logr->ssl.ciphers);
            os_strdup(node[j]->content, logr->ssl.ciphers);
        } else {
            merror(XML_INVELEM, node[j]->element);
            return (OS_INVALID);
        }
    }

    return (0);
}

int Read_Agent_Report(XML_NODE node, agent_report * report)
{
    /* XML definitions - shared by <stats_report> and <config_report> (#37843);
     * <interval> takes the usual suffixes: <interval>1h</interval>. */
    const char *xml_enabled = "enabled";
    const char *xml_interval = "interval";

    /* Same ceiling as <batch>: a day between snapshots is already past useless,
     * and it keeps the value the module wants inside 32 bits. */
    const long max_interval = 86400;

    for (int j = 0; node[j]; j++) {
        if (!node[j]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[j]->content) {
            merror(XML_VALUENULL, node[j]->element);
            return (OS_INVALID);
        } else if (strcmp(node[j]->element, xml_enabled) == 0) {
            if (strcmp(node[j]->content, "yes") == 0) {
                report->enabled = 1;
            } else if (strcmp(node[j]->content, "no") == 0) {
                report->enabled = 0;
            } else {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_interval) == 0) {
            const long interval = w_parse_time(node[j]->content);

            if (interval <= 0 || interval > max_interval) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }

            report->interval = interval;
        } else {
            merror(XML_INVELEM, node[j]->element);
            return (OS_INVALID);
        }
    }

    return (0);
}

int Read_Agent_Batch(XML_NODE node, agent * logr)
{
    /* XML definitions - the <agent><batch> block (#37835). Both accept the
     * usual suffixes: <size>1MB</size>, <interval>10s</interval>. */
    const char *xml_size = "size";
    const char *xml_interval = "interval";

    /* An interval this long already dwarfs any sane batching window, and it
     * keeps the milliseconds the module wants inside 32 bits. */
    const long max_interval = 86400;

    /* Upper bound so the value survives the trip into a 32-bit agent's size_t, where
     * anything past 4 GiB wraps -- and exactly 4 GiB wraps to zero, which every reader
     * takes as "unset". A gigabyte is already far past useful: the stateless
     * accumulator reserves a multiple of this, and one sync session is held to it. */
    const long long max_size = 1024LL * 1024 * 1024;

    for (int j = 0; node[j]; j++) {
        if (!node[j]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[j]->content) {
            merror(XML_VALUENULL, node[j]->element);
            return (OS_INVALID);
        } else if (strcmp(node[j]->element, xml_size) == 0) {
            const long long size = w_validate_bytes(node[j]->content);

            if (size <= 0 || size > max_size) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }

            logr->batch.size = size;
        } else if (strcmp(node[j]->element, xml_interval) == 0) {
            const long interval = w_parse_time(node[j]->content);

            if (interval <= 0 || interval > max_interval) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }

            logr->batch.interval = interval;
        } else {
            merror(XML_INVELEM, node[j]->element);
            return (OS_INVALID);
        }
    }

    return (0);
}

/**
 * @brief Read <batch> out of one <agent> block, ignoring every other option.
 * @return 0 on success, OS_INVALID when the block does not parse.
 */
static int read_batch_of_agent_block(const OS_XML *xml, xml_node *agent_node, agent *out)
{
    XML_NODE options = OS_GetElementsbyNode(xml, agent_node);
    int result = 0;

    for (int i = 0; options && options[i]; i++) {
        XML_NODE limits = NULL;

        if (!options[i]->element || strcmp(options[i]->element, "batch") != 0) {
            continue;
        }

        if ((limits = OS_GetElementsbyNode(xml, options[i]))) {
            if (Read_Agent_Batch(limits, out) < 0) {
                result = OS_INVALID;
            }

            OS_ClearNode(limits);
        }
    }

    OS_ClearNode(options);
    return result;
}

/**
 * @brief Walk one configuration root looking for <agent> blocks.
 * @return 0 on success, OS_INVALID when any of them does not parse.
 */
static int read_batch_of_root(const OS_XML *xml, xml_node *root_node, agent *out)
{
    XML_NODE blocks = OS_GetElementsbyNode(xml, root_node);
    int result = 0;

    for (int i = 0; blocks && blocks[i]; i++) {
        if (blocks[i]->element && strcmp(blocks[i]->element, "agent") == 0) {
            if (read_batch_of_agent_block(xml, blocks[i], out) < 0) {
                result = OS_INVALID;
            }
        }
    }

    OS_ClearNode(blocks);
    return result;
}

/**
 * @brief Read <agent><batch> straight out of a local configuration file.
 * @return 0 when the file had nothing to object to (including having nothing to say,
 *         or not being there at all), OS_INVALID when a block was rejected.
 */
static int read_local_agent_batch(const char *cfgfile, agent *out)
{
    OS_XML xml;
    XML_NODE root = NULL;
    int result = 0;

    if (OS_ReadXML(cfgfile, &xml) < 0) {
        /* Absent or unreadable: nothing to contribute, and not this function's to
         * report -- the daemon reads the same file for its own configuration and
         * fails loudly there. A failed read still leaves the object holding
         * whatever it allocated before giving up, so it is cleared either way. */
        OS_ClearXML(&xml);
        return 0;
    }

    root = OS_GetElementsbyNode(&xml, NULL);

    for (int i = 0; root && root[i]; i++) {
        if (read_batch_of_root(&xml, root[i], out) < 0) {
            result = OS_INVALID;
        }
    }

    OS_ClearNode(root);
    OS_ClearXML(&xml);
    return result;
}

/**
 * @brief Copy the limits one source set over what the caller already had.
 *
 * Each limit stands on its own, so a source naming only one leaves the other alone --
 * which is how the centralized block overrides just the parts it mentions.
 */
static void apply_agent_batch(const agent_batch *from, agent_batch *to)
{
    if (from->size > 0) {
        to->size = from->size;
    }

    if (from->interval > 0) {
        to->interval = from->interval;
    }
}

void w_read_agent_batch(const char *cfgfile, const char *sharedcfg, agent_batch *batch)
{
    agent local = { .server = NULL };
    agent shared = { .server = NULL };

    if (!batch) {
        return;
    }

    /* Read_Agent_Batch fills each limit as it walks it, so a block whose second
     * element is invalid has already assigned the first. Nothing is applied unless the
     * read comes back clean: a rejected configuration must leave the caller on its
     * defaults, not on the half of it that happened to parse. */
    if (cfgfile && read_local_agent_batch(cfgfile, &local) < 0) {
        return;
    }

    apply_agent_batch(&local.batch, batch);

    /* The centralized file goes through ReadConfig so it gets the same
     * agent_config name/os/profile filtering every other module gets; the local
     * one cannot, because Read_Agent expects structures agentd sets up first.
     *
     * Checked for existence first because ReadConfig answers OS_INVALID for a file
     * that is merely absent, and most agents have never been pushed one -- without
     * this, "no shared configuration" would throw away the local <batch> too.
     *
     * Read into a struct of its own so a rejected centralized block cannot be
     * half-applied on top of a local one that did parse, and so that local one still
     * stands when the centralized file is unusable. That last part is what agentd
     * already does with the same two files -- ClientConf does not check this call at
     * all -- and without it one agent runs two different session limits, agentd on
     * the local value and syscheckd and the modules on the built-in default.
     *
     * Warned about here because ReadConfig stays quiet on the agent: its XML_ERROR is
     * compiled out under CLIENT for centralized reads, so nothing else says why the
     * pushed limits were ignored. */
    if (sharedcfg && w_is_file(sharedcfg) &&
            ReadConfig(CCLIENT | CAGENT_CONFIG, sharedcfg, &shared, NULL) < 0) {
        mwarn("Could not read the centralized configuration '%s'. Keeping the local <agent><batch> limits.",
              sharedcfg);
        return;
    }

    apply_agent_batch(&shared.batch, batch);
}

int Read_Agent_Enrollment(XML_NODE node, agent * logr){
    /* XML definitions */
    const char *xml_enabled = "enabled";
    const char *xml_manager_addr = "manager_address";
    const char *xml_port = "port";
    const char *xml_interface = "interface_index";
    const char *xml_agent_name = "agent_name";
    const char *xml_groups = "groups";
    const char *xml_agent_addr = "agent_address";
    const char *xml_ssl_cipher = "ssl_cipher";
    const char *xml_server_ca_path = "server_ca_path";
    const char *xml_agent_certif_path = "agent_certificate_path";
    const char *xml_agent_key_path = "agent_key_path";
    const char *xml_auth_password_path = "authorization_pass_path";
    const char *xml_delay_after_enrollment = "delay_after_enrollment";
    const char *xml_use_source_ip = "use_source_ip";
    char * remote_ip = NULL;
    int port = 0;
    int j;
    char f_ip[128];


    w_enrollment_cert *cert_cfg = logr->enrollment_cfg->cert_cfg;
    w_enrollment_target *target_cfg = logr->enrollment_cfg->target_cfg;

    for (j = 0; node[j]; j++) {
        if (!node[j]->element) {
            merror(XML_ELEMNULL);
            w_enrollment_target_destroy(target_cfg);
            w_enrollment_cert_destroy(cert_cfg);
            return (OS_INVALID);
        } else if (!node[j]->content) {
            merror(XML_VALUENULL, node[j]->element);
            w_enrollment_target_destroy(target_cfg);
            w_enrollment_cert_destroy(cert_cfg);
            return (OS_INVALID);
        } else if (!strcmp(node[j]->element, xml_enabled)) {
            if (!strcmp(node[j]->content, "yes"))
                logr->enrollment_cfg->enabled = true;
            else if (!strcmp(node[j]->content, "no")) {
                logr->enrollment_cfg->enabled = false;
            } else {
                merror("Invalid content for tag '%s'.", node[j]->element);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return OS_INVALID;
            }
        }
        else if (strcmp(node[j]->element, xml_manager_addr) == 0) {
            if (OS_IsValidIP(node[j]->content, NULL) == 1) {
                remote_ip = node[j]->content;
            } else if (strchr(node[j]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s", node[j]->content);
                remote_ip = f_ip;
            } else {
                merror(AG_INV_HOST, node[j]->content);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return (OS_INVALID);
            }
            os_free(target_cfg->manager_name);
            os_strdup(remote_ip, target_cfg->manager_name);
            if (strchr(target_cfg->manager_name, ':') != NULL) {
                os_realloc(target_cfg->manager_name, IPSIZE + 1, target_cfg->manager_name);
                OS_ExpandIPv6(target_cfg->manager_name, IPSIZE);
            }
        } else if (strcmp(node[j]->element, xml_port) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return (OS_INVALID);
            }
            if (port = atoi(node[j]->content), port <= 0 || port > 65535) {
                merror(PORT_ERROR, port);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return (OS_INVALID);
            }
            target_cfg->port = port;
        } else if (strcmp(node[j]->element, xml_interface) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return (OS_INVALID);
            }
            int interface_numeric = atoi(node[j]->content);
            if (interface_numeric <= 0) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return (OS_INVALID);
            }
            target_cfg->network_interface = (uint32_t)interface_numeric;
        } else if (strcmp(node[j]->element, xml_agent_name) == 0) {
            os_free(target_cfg->agent_name);
            os_strdup(node[j]->content, target_cfg->agent_name);
        } else if (strcmp(node[j]->element, xml_groups) == 0) {
            os_free(target_cfg->centralized_group);
            os_strdup(node[j]->content, target_cfg->centralized_group);
        } else if (strcmp(node[j]->element, xml_agent_addr) == 0) {
            if (OS_IsValidIP(node[j]->content, NULL) != 0) {
                os_free(target_cfg->sender_ip);
                os_strdup(node[j]->content, target_cfg->sender_ip);
                if (strchr(target_cfg->sender_ip, ':') != NULL) {
                    os_realloc(target_cfg->sender_ip, IPSIZE + 1, target_cfg->sender_ip);
                    OS_ExpandIPv6(target_cfg->sender_ip, IPSIZE);
                }
            } else {
                merror(AG_INV_HOST, node[j]->content);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_ssl_cipher) == 0) {
            os_free(cert_cfg->ciphers);
            os_strdup(node[j]->content, cert_cfg->ciphers);
        } else if (strcmp(node[j]->element, xml_server_ca_path) == 0) {
            os_free(cert_cfg->ca_cert);
            os_strdup(node[j]->content, cert_cfg->ca_cert);
        } else if (strcmp(node[j]->element, xml_agent_certif_path) == 0) {
            os_free(cert_cfg->agent_cert);
            os_strdup(node[j]->content, cert_cfg->agent_cert);
        } else if (strcmp(node[j]->element, xml_agent_key_path) == 0) {
            os_free(cert_cfg->agent_key);
            os_strdup(node[j]->content, cert_cfg->agent_key);
        } else if (strcmp(node[j]->element, xml_auth_password_path) == 0) {
            os_free(cert_cfg->authpass_file);
            os_strdup(node[j]->content, cert_cfg->authpass_file);
        } else if (strcmp(node[j]->element, xml_delay_after_enrollment) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return (OS_INVALID);
            }
            int delay_after_enrollment;
            if (delay_after_enrollment = atoi(node[j]->content), delay_after_enrollment <= 0) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return (OS_INVALID);
            }
            logr->enrollment_cfg->delay_after_enrollment = delay_after_enrollment;
        } else if (strcmp(node[j]->element, xml_use_source_ip) == 0) {
            if (!strcmp(node[j]->content, "yes")) {
                target_cfg->use_src_ip = 1;
            } else if (!strcmp(node[j]->content, "no")) {
                target_cfg->use_src_ip = 0;
            } else {
                merror("Invalid content for tag '%s'.", node[j]->element);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return OS_INVALID;
            }
        } else {
            merror(XML_INVELEM, node[j]->element);
            w_enrollment_target_destroy(target_cfg);
            w_enrollment_cert_destroy(cert_cfg);
            return (OS_INVALID);
        }
    }
    return 0;
}
int Read_AntiTampering(XML_NODE node, void *d1) {
    /* XML definitions */
    const char *xml_package_uninstallation = "package_uninstallation";

    anti_tampering *atc = (anti_tampering *)d1;

    for (int j = 0; node[j]; j++) {
        if (!node[j]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[j]->content) {
            merror(XML_VALUENULL, node[j]->element);
            return (OS_INVALID);
        } else if (!strcmp(node[j]->element, xml_package_uninstallation)) {
            if (!strcmp(node[j]->content, "yes"))
                atc->package_uninstallation = true;
            else if (!strcmp(node[j]->content, "no")) {
                atc->package_uninstallation = false;
            } else {
                merror("Invalid content for tag '%s'.", node[j]->element);
                return OS_INVALID;
            }
        } else {
            merror(XML_INVELEM, node[j]->element);
            return (OS_INVALID);
        }
    }
    return 0;
}

int Test_Agent(const char * path){
    int fail = 0;
    agent test_agent = { .server = NULL };

    if (ReadConfig(CAGENT_CONFIG | CCLIENT, path, &test_agent, NULL) < 0) {
		merror(RCONFIG_ERROR,"Client", path);
		fail = 1;
	}

    Free_Agent(&test_agent);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}

void Free_Agent(agent * config){
    if (config) {
        int i;

        if (config->server) {
            for (i = 0; config->server[i].rip; i++) {
                free(config->server[i].rip);
            }

            free(config->server);
        }

        free(config->profile);

        os_free(config->ssl.certificate);
        os_free(config->ssl.key);
        os_free(config->ssl.certificate_authorities);
        os_free(config->ssl.ciphers);
    }
}

/* Check if is valid server addres */
bool Validate_Address(agent_server *servers)
{
    int i;

    for (i = 0; servers[i].rip; i++) {

        if ( strcmp(servers[i].rip, "MANAGER_IP") != 0
            && strcmp(servers[i].rip, "0.0.0.0") != 0
            && strlen(servers[i].rip) > 0 ){

            return true;
        }
    }

    return false;
}

/* Checks if at least one <manager> block is not a link-local ipv6 address or it has a network interface configured. */
bool Validate_IPv6_Link_Local_Interface(agent_server *servers) {
    unsigned int i;
    bool ret = false;

    for (i = 0; servers[i].rip; i++) {
        char *ip_address = NULL;
        char *tmp_str = strchr(servers[i].rip, '/');
        if (tmp_str) {
            // server address comes in {hostname}/{ip} format
            ip_address = strdup(++tmp_str);
        }
        if (!ip_address) {
            // server address is either a host or a ip
            ip_address = OS_GetHost(servers[i].rip, 3);
        }

        /* The hostname was not resolved correctly */
        if (ip_address == NULL || *ip_address == '\0') {
            if (servers[i].rip != NULL) {
                const int rip_l = strlen(servers[i].rip);
                mdebug1("Could not resolve hostname '%.*s'", servers[i].rip[rip_l - 1] == '/' ? rip_l - 1 : rip_l, servers[i].rip);
            } else {
                mdebug1("Could not resolve hostname");
            }
            os_free(ip_address);
            ret = true;
            continue;
        }

        if (strchr(ip_address, ':') != NULL) {
            /* IPv6 */
            if (strncmp(ip_address, IPV6_LINK_LOCAL_PREFIX, 20) != 0 ||
                (strncmp(ip_address, IPV6_LINK_LOCAL_PREFIX, 20) == 0 && servers[i].network_interface > 0)) {
                os_free(ip_address);
                ret = true;
                continue;
            }
            else if ((strncmp(ip_address, IPV6_LINK_LOCAL_PREFIX, 20) == 0 && servers[i].network_interface <= 0)) {
                mwarn("No network interface index provided to use %s link-local IPv6 address.", ip_address);
            }
        } else {
            /* IPv4 */
            ret = true;
        }
        os_free(ip_address);
    }

    return ret;
}
