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

/* #38624: <endpoint> is parsed with libcurl's URL API. Already a dependency here --
 * shared/src/url.c links the same library -- so this adds no new one. */
#include <errno.h>
#include "urlapi.h"

/* if_nametoindex(), for resolving an IPv6 zone id to a scope id (#38624). Windows
 * declares it in netioapi.h and provides it from iphlpapi, which every agent binary
 * and the winagent unit tests already link. */
#ifdef WIN32
#include <netioapi.h>
#else
#include <net/if.h>
#endif

/* #38492: validation bound for <endpoint>, well under hc_config_t::server_endpoint's
 * HC_MAX_ENDPOINT (256) so the C++ bridge's strncpy() never truncates a value
 * that passed validation here. */
#define AGENT_SERVER_ENDPOINT_MAX_LEN 128

/* #38624: bound for the host component, matching hc_config_t::server_host (HC_MAX_HOST,
 * 256) for the same reason. */
#define AGENT_SERVER_HOST_MAX_LEN 255

static int w_parse_agent_endpoint(const char *raw, char *host, size_t host_size, int *port,
                                  bool *port_present, char *endpoint, size_t endpoint_size,
                                  uint32_t *scope_id);

int Read_Agent_Manager(XML_NODE node, agent *logr);
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
    const char *xml_agent_manager = "manager";
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
            mwarn("The <%s> tag is deprecated, please use <manager><endpoint> instead.", xml_agent_ip);

            if (OS_IsValidIP(node[i]->content, NULL) != 1) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            }

            rip = node[i]->content;
        } else if (strcmp(node[i]->element, xml_agent_hostname) == 0) {
            mwarn("The <%s> tag is deprecated, please use <manager><endpoint> instead.", xml_agent_hostname);
            if (strchr(node[i]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s/", node[i]->content);
                rip = f_ip;
            } else {
                merror(AG_INV_HOST, node[i]->content);
                return (OS_INVALID);
            }

        }
        /* Get parameters for the configured manager block */
        else if (strcmp(node[i]->element, xml_agent_manager) == 0) {
            if (!(chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                merror(XML_INVELEM, node[i]->element);
                return (OS_INVALID);
            }
            if (Read_Agent_Manager(chld_node, logr) < 0) {
                OS_ClearNode(chld_node);
                return (OS_INVALID);
            }
            OS_ClearNode(chld_node);
        } else if (strcmp(node[i]->element, xml_agent_ssl) == 0) {
            /* HTTPS transport TLS settings (sibling of <manager>, #37702 §10). */
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
            // os_realloc() does not zero new memory; this old <server-ip>/<server-hostname>
            // syntax never had an <endpoint> concept, so default it the same way a WPK-upgraded
            // 4.x <client><server> config does (see Read_Legacy_Client_Address()).
            os_strdup(DEFAULT_AGENT_ENDPOINT_PREFIX, logr->server[logr->server_count].endpoint);
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
    const char *xml_client_server = "server";
    const char *xml_client_addr = "address";
    const char *xml_client_endpoint = "endpoint";
    char * address = NULL;
    char * endpoint_value = NULL;

    agent * logr = (agent *)d1;

    if (logr->server) {
        return (0);
    }

    for (int i = 0; node[i]; i++) {
        XML_NODE chld_node = NULL;

        if (!node[i]->element || strcmp(node[i]->element, xml_client_server) != 0) {
            continue;
        }

        if (!(chld_node = OS_GetElementsbyNode(xml, node[i]))) {
            continue;
        }

        for (int j = 0; chld_node[j]; j++) {
            if (!chld_node[j]->element || !chld_node[j]->content) {
                continue;
            }

            if (strcmp(chld_node[j]->element, xml_client_addr) == 0) {
                os_free(address);
                os_strdup(chld_node[j]->content, address);
            } else if (strcmp(chld_node[j]->element, xml_client_endpoint) == 0) {
                /* The MSI reconfigures a preserved 4.x file in place and, having no
                 * <agent> block to target, writes the endpoint into this <server> one.
                 * Reading only <address> here left that agent with no manager at all. */
                os_free(endpoint_value);
                os_strdup(chld_node[j]->content, endpoint_value);
            }
        }

        OS_ClearNode(chld_node);
    }

    /* An <endpoint> written here by the installer carries the whole target, so it wins
     * and is parsed exactly as one under <agent><manager> would be. */
    if (endpoint_value) {
        char host[AGENT_SERVER_HOST_MAX_LEN + 1] = {'\0'};
        char endpoint[AGENT_SERVER_ENDPOINT_MAX_LEN + 1] = {'\0'};
        uint32_t scope_id = 0;
        int port = DEFAULT_HTTPS_REMOTE_PORT;
        bool port_present = false;

        if (w_parse_agent_endpoint(endpoint_value, host, sizeof(host), &port, &port_present,
                                   endpoint, sizeof(endpoint), &scope_id) == OS_INVALID) {
            os_free(address);
            os_free(endpoint_value);
            return (OS_INVALID);
        }

        os_free(address);
        os_free(endpoint_value);

        os_calloc(2, sizeof(agent_server), logr->server);
        os_strdup(host, logr->server[0].rip);

        if (strchr(logr->server[0].rip, ':') != NULL) {
            os_realloc(logr->server[0].rip, IPSIZE + 1, logr->server[0].rip);
            OS_ExpandIPv6(logr->server[0].rip, IPSIZE);
        }

        if (endpoint[0] != '\0') {
            os_strdup(endpoint, logr->server[0].endpoint);
        }

        logr->server[0].scope_id = scope_id;
        logr->server[0].port = port;
        logr->server_count = 1;

        return (0);
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
    /* 4.x had no <endpoint> concept at all -- any <port> under this legacy
     * <client><server> block was never read either (see this function's own
     * docstring), so a WPK-upgraded agent always reconnects on the 5.x HTTPS
     * port with the manager's default reverse-proxy prefix, never the old
     * 4.x port or unprefixed requests. */
    os_strdup(DEFAULT_AGENT_ENDPOINT_PREFIX, logr->server[0].endpoint);
    logr->server_count = 1;

    /* A 4.x file has no <endpoint> at all, so say exactly what to write -- this is the
     * upgrade path most likely to be edited by hand, and a copy-pasteable line is the
     * whole point. The composed value is the one now in use, so pasting it changes
     * nothing about where the agent connects. */
    minfo("<agent><manager><endpoint> is not configured. Using <client><server><address> '%s' "
          "with the default port %d and the default endpoint prefix '%s'. Replace the "
          "<client><server> block with a single <endpoint>%s%s%s:%d/%s</endpoint>",
          logr->server[0].rip, DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX,
          (strchr(logr->server[0].rip, ':') != NULL) ? "[" : "",
          logr->server[0].rip,
          (strchr(logr->server[0].rip, ':') != NULL) ? "]" : "",
          DEFAULT_HTTPS_REMOTE_PORT, DEFAULT_AGENT_ENDPOINT_PREFIX);

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
 * @brief Validate and normalize a present <endpoint> tag's content (#38492).
 *
 * Only called with the raw content of an <endpoint> tag that was actually found in
 * the XML -- an entirely absent tag never reaches this function; see
 * Read_Agent_Manager()'s `endpoint_set`, which now defaults that case to
 * DEFAULT_AGENT_ENDPOINT_PREFIX instead of leaving it unprefixed.
 *
 * Strips leading and trailing '/' characters (so "/wazuh-manager/",
 * "wazuh-manager", and "wazuh-manager/" all normalize the same way),
 * then rejects anything outside [A-Za-z0-9._-] plus '/' as an internal
 * segment separator, repeated '/' (an empty segment), and '.'/'..'
 * segments. A *present* endpoint that normalizes to empty ("/" or "")
 * is a deliberate opt-out and still means "no endpoint configured" --
 * unprefixed requests, unlike the entirely-absent case above.
 *
 * The manager-side sister issue must accept exactly the same charset,
 * or an endpoint this agent accepts could still fail to route once it
 * reaches the manager's reverse proxy.
 *
 * @param raw Raw XML content (never NULL).
 * @param out Buffer to receive the normalized value.
 * @param out_size Size of out, including the terminating NUL.
 * @return 0 on success (out holds the normalized value, possibly ""), OS_INVALID on error.
 */
static int w_normalize_agent_endpoint(const char *raw, char *out, size_t out_size)
{
    size_t start = 0;
    size_t end = strlen(raw);

    while (start < end && raw[start] == '/') {
        start++;
    }

    while (end > start && raw[end - 1] == '/') {
        end--;
    }

    size_t len = end - start;

    if (len == 0) {
        out[0] = '\0';
        return 0;
    }

    if (len >= out_size) {
        merror("Invalid endpoint '%s': longer than %zu characters.", raw, out_size - 1);
        return OS_INVALID;
    }

    memcpy(out, raw + start, len);
    out[len] = '\0';

    bool previous_was_slash = false;
    size_t segment_start = 0;

    for (size_t i = 0; i <= len; i++) {
        if (i < len) {
            char c = out[i];
            bool is_slash = (c == '/');

            if (!(isalnum((unsigned char)c) || c == '-' || c == '_' || c == '.' || is_slash)) {
                merror("Invalid endpoint '%s': only letters, digits, '-', '_', '.', and '/' "
                       "(as a segment separator) are allowed.", raw);
                return OS_INVALID;
            }

            if (is_slash && previous_was_slash) {
                merror("Invalid endpoint '%s': empty path segment (repeated '/').", raw);
                return OS_INVALID;
            }

            previous_was_slash = is_slash;
        }

        if (i == len || out[i] == '/') {
            size_t segment_len = i - segment_start;

            if ((segment_len == 1 && out[segment_start] == '.') ||
                    (segment_len == 2 && out[segment_start] == '.' && out[segment_start + 1] == '.')) {
                merror("Invalid endpoint '%s': '.' and '..' are not allowed path segments.", raw);
                return OS_INVALID;
            }

            segment_start = i + 1;
        }
    }

    return 0;
}

/**
 * @brief Resolve an IPv6 zone id (interface name or numeric index) to a scope id (#38624).
 *
 * A link-local IPv6 address is ambiguous without a scope: fe80::1 may exist on
 * several interfaces at once. The zone id names the one to use, spelled with a
 * percent inside the brackets -- and because that percent lives in a URL, it
 * arrives percent-encoded: [fe80::1%25eth0].
 *
 * Accepts either an interface name, resolved through if_nametoindex(), or an
 * already-numeric index passed through as-is. Resolving here rather than at
 * connect time means an unknown interface is a startup configuration error with
 * the interface named, instead of an opaque failure from libcurl later on.
 *
 * @param zone Zone id text, already percent-decoded (never NULL, never empty).
 * @param out Receives the numeric scope id.
 * @return 0 on success, OS_INVALID when the interface does not exist.
 */
static int w_resolve_ipv6_zone(const char *zone, uint32_t *out)
{
    if (OS_StrIsNum(zone)) {
        char *end = NULL;
        unsigned long numeric;

        /* strtoul, not strtol: long is 32-bit on MinGW, where "> UINT32_MAX" is
         * unreachable and an overflowing value came back as LONG_MAX and was accepted.
         * errno is the only way to see that saturation. */
        errno = 0;
        numeric = strtoul(zone, &end, 10);

        if (errno == ERANGE || end == zone || (end && *end != '\0') ||
            numeric == 0 || numeric > UINT32_MAX) {
            merror("Invalid endpoint: IPv6 zone id '%s' is out of range.", zone);
            return OS_INVALID;
        }

        *out = (uint32_t)numeric;
        return 0;
    }

    unsigned int index = if_nametoindex(zone);

    if (index == 0) {
        merror("Invalid endpoint: no network interface named '%s' on this host.", zone);
        return OS_INVALID;
    }

    *out = (uint32_t)index;
    return 0;
}

/**
 * @brief Parse the combined <endpoint> value into host, port, prefix and scope id (#38624).
 *
 * <endpoint> carries the whole connection target in one value, in the same
 * language the WAZUH_MANAGER_ENDPOINT installation variable accepts, so the
 * installers can write an operator's value through verbatim:
 *
 *     [https://] host [:port] [/[prefix]]
 *
 * Only the host is mandatory. An omitted port defaults to DEFAULT_HTTPS_REMOTE_PORT
 * and an omitted prefix to DEFAULT_AGENT_ENDPOINT_PREFIX, so a bare address behaves
 * exactly as it did when <address> and <port> were separate tags.
 *
 * Parsing goes through libcurl's URL API rather than by hand: it is already linked
 * here (shared/src/url.c uses it), and it brings host/port syntax checks, IPv6
 * bracket handling and zone-id extraction with it. A scheme-less value gets an
 * "https://" prepended first, so one parser serves both spellings.
 *
 * The one thing curl cannot answer: CURLUPART_PATH always reports at least "/",
 * so it cannot tell "no path was given" from "a trailing slash and nothing more".
 * That is exactly the distinction the prefix opt-out rests on (#38614) -- no
 * separator means the default prefix, a separator with nothing after it means
 * unprefixed -- so the separator is looked for in the raw value instead, the way
 * the installers' own parsers do. Losing it would silently turn every opt-out back
 * into the default, which is the defect #38658 fixed elsewhere.
 *
 * @param raw Raw <endpoint> content (never NULL).
 * @param host Receives the host, brackets and zone id stripped.
 * @param host_size Size of host, including the terminating NUL.
 * @param port Receives the port.
 * @param endpoint Receives the normalized prefix, possibly "".
 * @param endpoint_size Size of endpoint, including the terminating NUL.
 * @param scope_id Receives the IPv6 scope id, or 0 when there is no zone id.
 * @return 0 on success, OS_INVALID on any grammar violation.
 */
static int w_parse_agent_endpoint(const char *raw, char *host, size_t host_size, int *port,
                                  bool *port_present, char *endpoint, size_t endpoint_size,
                                  uint32_t *scope_id)
{
    CURLU *url = NULL;
    char *part = NULL;
    char *with_scheme = NULL;
    int retval = OS_INVALID;

    *scope_id = 0;
    *port_present = false;
    *port = DEFAULT_HTTPS_REMOTE_PORT;
    endpoint[0] = '\0';
    host[0] = '\0';

    if (*raw == '\0') {
        merror("Invalid endpoint '%s': a manager address is required.", raw);
        return OS_INVALID;
    }

    /* A leading '/' means a prefix was given where the address belongs -- the 5.0.0
     * spelling arriving without the <address> that used to accompany it. Rejected
     * explicitly because curl would otherwise read "https:///wazuh-manager/" as the
     * hostname "wazuh-manager" and silently connect somewhere unintended. */
    if (*raw == '/') {
        merror("Invalid endpoint '%s': a manager address is required before the path.", raw);
        return OS_INVALID;
    }

    /* Whether a path separator was given at all, decided before curl sees the value
     * and ignoring one that belongs to a "scheme://" rather than to the path. */
    const char *authority = strstr(raw, "://");
    authority = authority ? authority + 3 : raw;
    bool path_given = (strchr(authority, '/') != NULL);

    if (strstr(raw, "://") == NULL) {
        const size_t needed = strlen("https://") + strlen(raw) + 1;
        os_calloc(needed, sizeof(char), with_scheme);
        snprintf(with_scheme, needed, "https://%s", raw);
    }

    url = curl_url();

    if (url == NULL) {
        merror("Invalid endpoint '%s': could not initialize the URL parser.", raw);
        goto end;
    }

    /* CURLU_DISALLOW_USER makes curl itself reject embedded credentials.
     * CURLU_PATH_AS_IS keeps "." and ".." segments intact: curl would otherwise
     * resolve them away, so "/../etc" would silently become "/etc" instead of being
     * rejected by w_normalize_agent_endpoint(). A configured value must never be
     * quietly rewritten into a different one. */
    CURLUcode rc = curl_url_set(url, CURLUPART_URL, with_scheme ? with_scheme : raw,
                                CURLU_DISALLOW_USER | CURLU_PATH_AS_IS);

    if (rc != CURLUE_OK) {
        merror("Invalid endpoint '%s': %s.", raw, curl_url_strerror(rc));
        goto end;
    }

    if (curl_url_get(url, CURLUPART_SCHEME, &part, 0) != CURLUE_OK) {
        merror("Invalid endpoint '%s': missing scheme.", raw);
        goto end;
    }

    if (strcasecmp(part, "https") != 0) {
        merror("Invalid endpoint '%s': unsupported scheme '%s'; only https is served.", raw, part);
        goto end;
    }

    curl_free(part);
    part = NULL;

    /* A configuration value has to be exact, so anything curl parsed off the end
     * that this grammar has no slot for is an error rather than a silent drop. */
    if (curl_url_get(url, CURLUPART_QUERY, &part, 0) == CURLUE_OK) {
        merror("Invalid endpoint '%s': a query string is not allowed.", raw);
        goto end;
    }

    if (curl_url_get(url, CURLUPART_FRAGMENT, &part, 0) == CURLUE_OK) {
        merror("Invalid endpoint '%s': a fragment is not allowed.", raw);
        goto end;
    }

    if (curl_url_get(url, CURLUPART_HOST, &part, 0) != CURLUE_OK || *part == '\0') {
        merror("Invalid endpoint '%s': a manager address is required.", raw);
        goto end;
    }

    /* curl hands an IPv6 literal back still bracketed. Store it bare, the way
     * <address> always held it: OS_ExpandIPv6() and the link-local check in
     * Validate_IPv6_Link_Local_Interface() both compare against an unbracketed
     * literal, and ModuleConfig::baseUrl() re-brackets it for the wire itself. */
    const char *host_start = part;
    size_t host_len = strlen(part);

    if (host_len >= 2 && host_start[0] == '[' && host_start[host_len - 1] == ']') {
        host_start++;
        host_len -= 2;
    }

    if (host_len >= host_size) {
        merror("Invalid endpoint '%s': address longer than %zu characters.", raw, host_size - 1);
        goto end;
    }

    memcpy(host, host_start, host_len);
    host[host_len] = '\0';
    curl_free(part);
    part = NULL;

    /* A ':' with nothing after it is "no port" to curl, which would silently fall back
     * to the default; the installers reject it, so reject it here too rather than let
     * the same value mean different things either side of the install boundary. */
    {
        const char *authority_end = strchr(authority, '/');
        size_t authority_len = authority_end ? (size_t)(authority_end - authority) : strlen(authority);

        if (authority_len > 0 && authority[authority_len - 1] == ':') {
            merror("Invalid endpoint '%s': a ':' must be followed by a port.", raw);
            goto end;
        }
    }

    /* Deliberately without CURLU_DEFAULT_PORT: that substitutes curl's own https
     * default (443), not the agent's (1517). */
    if (curl_url_get(url, CURLUPART_PORT, &part, 0) == CURLUE_OK) {
        /* Range-checked here: curl accepts ":0" and would happily go on to connect,
         * while every installer parser rejects anything below 1. */
        long parsed = atol(part);

        if (parsed < 1 || parsed > 65535) {
            merror("Invalid endpoint '%s': port %ld is out of the range 1-65535.", raw, parsed);
            goto end;
        }

        *port = (int)parsed;
        *port_present = true;
        curl_free(part);
        part = NULL;
    }

    if (curl_url_get(url, CURLUPART_ZONEID, &part, 0) == CURLUE_OK) {
        if (w_resolve_ipv6_zone(part, scope_id) == OS_INVALID) {
            goto end;
        }
        curl_free(part);
        part = NULL;
    }

    if (path_given) {
        if (curl_url_get(url, CURLUPART_PATH, &part, 0) != CURLUE_OK) {
            merror("Invalid endpoint '%s': could not read the path.", raw);
            goto end;
        }

        /* curl always reports the path with its leading '/'. Strip it so the
         * normalizer -- and every message it emits -- sees the prefix exactly as the
         * operator wrote it, rather than a slash they did not type. */
        const char *prefix = (*part == '/') ? part + 1 : part;

        if (w_normalize_agent_endpoint(prefix, endpoint, endpoint_size) == OS_INVALID) {
            goto end;
        }
    } else {
        snprintf(endpoint, endpoint_size, "%s", DEFAULT_AGENT_ENDPOINT_PREFIX);
    }

    retval = 0;

end:
    if (part != NULL) {
        curl_free(part);
    }
    if (url != NULL) {
        curl_url_cleanup(url);
    }
    os_free(with_scheme);

    return retval;
}

/**
 * @brief Read the <agent><manager> block: the single manager endpoint.
 *
 * @param node Children of the <manager> element.
 * @param logr Agent configuration to fill.
 * @return 0 on success, OS_INVALID on error.
 */
int Read_Agent_Manager(XML_NODE node, agent * logr)
{
    /* XML definitions */
    const char *xml_agent_addr = "address";
    const char *xml_agent_port = "port";
    const char *xml_agent_endpoint = "endpoint";
    const char *xml_protocol = "protocol";
    const char *xml_max_retries = "max_retries";
    const char *xml_retry_interval = "retry_interval";

    int j;
    char f_ip[128];
    char * rip = NULL;
    char * legacy_rip = NULL;
    char host[AGENT_SERVER_HOST_MAX_LEN + 1] = {'\0'};
    char endpoint[AGENT_SERVER_ENDPOINT_MAX_LEN + 1] = {'\0'};
    /* Default values */
    uint32_t scope_id = 0;
    int port = DEFAULT_HTTPS_REMOTE_PORT;
    bool port_set = false;
    int legacy_port = DEFAULT_HTTPS_REMOTE_PORT;
    bool legacy_port_set = false;
    bool endpoint_set = false;
    bool legacy_tags_used = false;
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
        /* Deprecated: <address> and <port> were folded into <endpoint> (#38624). Still
         * read so a hand-written configuration, or one left by a 5.0.0 development build
         * using the previous spelling, keeps working -- an upgrade never rewrites
         * ossec.conf. No released package emitted them: <agent><manager> itself landed
         * after v5.0.0-beta4. A real 4.x file spells this <client><server><address>,
         * which Read_Legacy_Client_Address() handles. */
        else if (strcmp(node[j]->element, xml_agent_addr) == 0) {
            if (OS_IsValidIP(node[j]->content, NULL) == 1) {
                legacy_rip = node[j]->content;
            } else if (strchr(node[j]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s", node[j]->content);
                legacy_rip = f_ip;
            } else {
                merror(AG_INV_HOST, node[j]->content);
                return (OS_INVALID);
            }
            legacy_tags_used = true;
        } else if (strcmp(node[j]->element, xml_agent_port) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }

            if (legacy_port = atoi(node[j]->content), legacy_port <= 0 || legacy_port > 65535) {
                merror(PORT_ERROR, legacy_port);
                return (OS_INVALID);
            }

            legacy_port_set = true;
            legacy_tags_used = true;
        } else if (strcmp(node[j]->element, xml_agent_endpoint) == 0) {
            /* <endpoint> always carries the whole target (#38624). The 5.0.0 spelling
             * that put only a prefix here shipped in no public release, so there is no
             * configuration in the field where this value means anything else -- and
             * without that case "wazuh-manager" is unambiguously a hostname. */
            if (w_parse_agent_endpoint(node[j]->content, host, sizeof(host), &port,
                                       &port_set, endpoint, sizeof(endpoint),
                                       &scope_id) == OS_INVALID) {
                return (OS_INVALID);
            }

            endpoint_set = true;
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

    /* <endpoint> wins over the deprecated pair whatever order they appeared in: it is
     * the canonical spelling, and the installers give WAZUH_MANAGER_ENDPOINT the same
     * priority over WAZUH_MANAGER/WAZUH_MANAGER_PORT. */
    if (endpoint_set) {
        rip = host;

        if (legacy_tags_used) {
            mwarn("<agent><manager><address> and <port> are ignored when <endpoint> is "
                  "configured; <endpoint> carries the whole target.");
            legacy_tags_used = false;
        }
    } else {
        rip = legacy_rip;
        port = legacy_port;
        port_set = legacy_port_set;
    }

    if (!rip) {
        merror("No manager <endpoint> in the configuration.");
        return (OS_INVALID);
    }


    /* Single <manager> block: the last one prevails (#37702 restriction 2) and
     * server rotation is removed (restriction 3), so replace any previous entry
     * instead of appending. The array keeps a NULL-rip sentinel at index 1. */
    if (logr->server) {
        if (logr->server_count > 0) {
            mwarn("Only one <manager> block is supported; the last one prevails.");
        }
        for (int k = 0; logr->server[k].rip; k++) {
            os_free(logr->server[k].rip);
            os_free(logr->server[k].endpoint);
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

    /* <endpoint> absent entirely: default to the manager's own default prefix so an
     * unconfigured agent still matches a manager using its default global_prefix
     * (#38491). An explicit opt-out (endpoint present but normalizing to nothing,
     * e.g. "/") is preserved as-is and left unprefixed -- only "tag never appeared"
     * gets the default. */
    if (!endpoint_set) {
        snprintf(endpoint, sizeof(endpoint), "%s", DEFAULT_AGENT_ENDPOINT_PREFIX);
    }

    if (endpoint[0] != '\0') {
        os_strdup(endpoint, logr->server[0].endpoint);
    }
    logr->server[0].scope_id = scope_id;
    logr->server[0].port = port;

    /* #38624: <address>/<port> still work, but tell the operator exactly what to write
     * instead. The suggestion is built from the values just resolved -- not from the
     * defaults -- so a prefix-only <endpoint> in the same block is preserved and pasting
     * the line back cannot change where the agent connects. INFO rather than WARNING:
     * nothing is wrong, the configuration is simply written in the older spelling. */
    if (legacy_tags_used) {
        /* The trailing '/' is always emitted: with a prefix it separates it, and with
         * none it is the opt-out spelling -- so an <endpoint></endpoint> opt-out is
         * suggested back as "host:port/" and keeps meaning the same thing. An IPv6
         * literal is bracketed, or its trailing group would read as the port. */
        const bool is_ipv6 = strchr(logr->server[0].rip, ':') != NULL;

        minfo("<agent><manager><address> and <port> are deprecated. Replace them with a "
              "single <endpoint>%s%s%s:%d/%s</endpoint>",
              is_ipv6 ? "[" : "", logr->server[0].rip, is_ipv6 ? "]" : "",
              port, endpoint);
    }
    logr->server[0].max_retries = max_retries;
    logr->server[0].retry_interval = retry_interval;
    logr->server_count = 1;

    /* Names <endpoint>, not the <port> tag: since #38624 the port is a component of
     * <endpoint>, so pointing the operator at a <port> element sends them looking for
     * something that no longer exists in a 5.x configuration. */
    if (!port_set) {
        minfo("No port in <agent><manager><endpoint>. Using the default port %d.",
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
            } else if (strcmp(node[j]->content, "system") == 0) {
                logr->ssl.verification_mode = AGENT_VERIFY_SYSTEM;
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
    const char *xml_agent_name = "agent_name";
    const char *xml_groups = "groups";
    const char *xml_agent_addr = "agent_address";
    const char *xml_auth_password_path = "authorization_pass_path";
    const char *xml_delay_after_enrollment = "delay_after_enrollment";
    const char *xml_use_source_ip = "use_source_ip";

    /* Superseded by <agent><manager>/<agent><ssl> (#38465): enrollment now
     * dials the same target and presents the same TLS material as every
     * other HTTPS endpoint, so a second address/port/interface/cert/key/CA
     * for it is redundant by design. Recognized-but-ignored rather than
     * rejected: an in-place 4.x->5.x upgrade never rewrites ossec.conf, so a
     * config still carrying these is the expected post-upgrade state, not an
     * operator mistake. */
    const char *xml_manager_addr = "manager_address";
    const char *xml_port = "port";
    const char *xml_interface = "interface_index";
    const char *xml_ssl_cipher = "ssl_cipher";
    const char *xml_server_ca_path = "server_ca_path";
    const char *xml_agent_certif_path = "agent_certificate_path";
    const char *xml_agent_key_path = "agent_key_path";

    int j;

    for (j = 0; node[j]; j++) {
        if (!node[j]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[j]->content) {
            merror(XML_VALUENULL, node[j]->element);
            return (OS_INVALID);
        } else if (strcmp(node[j]->element, xml_enabled) == 0) {
            if (strcmp(node[j]->content, "yes") == 0) {
                logr->enrollment.enabled = true;
            } else if (strcmp(node[j]->content, "no") == 0) {
                logr->enrollment.enabled = false;
            } else {
                merror("Invalid content for tag '%s'.", node[j]->element);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_agent_name) == 0) {
            os_free(logr->enrollment.agent_name);
            os_strdup(node[j]->content, logr->enrollment.agent_name);
        } else if (strcmp(node[j]->element, xml_groups) == 0) {
            os_free(logr->enrollment.groups);
            os_strdup(node[j]->content, logr->enrollment.groups);
        } else if (strcmp(node[j]->element, xml_agent_addr) == 0) {
            if (OS_IsValidIP(node[j]->content, NULL) != 0) {
                os_free(logr->enrollment.agent_address);
                os_strdup(node[j]->content, logr->enrollment.agent_address);
                if (strchr(logr->enrollment.agent_address, ':') != NULL) {
                    os_realloc(logr->enrollment.agent_address, IPSIZE + 1, logr->enrollment.agent_address);
                    OS_ExpandIPv6(logr->enrollment.agent_address, IPSIZE);
                }
            } else {
                merror(AG_INV_HOST, node[j]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_auth_password_path) == 0) {
            os_free(logr->enrollment.authorization_pass_path);
            os_strdup(node[j]->content, logr->enrollment.authorization_pass_path);
        } else if (strcmp(node[j]->element, xml_delay_after_enrollment) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
            int delay_after_enrollment;
            if (delay_after_enrollment = atoi(node[j]->content), delay_after_enrollment <= 0) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
            logr->enrollment.delay_after_enrollment = delay_after_enrollment;
        } else if (strcmp(node[j]->element, xml_use_source_ip) == 0) {
            if (strcmp(node[j]->content, "yes") == 0) {
                logr->enrollment.use_source_ip = true;
            } else if (strcmp(node[j]->content, "no") == 0) {
                logr->enrollment.use_source_ip = false;
            } else {
                merror("Invalid content for tag '%s'.", node[j]->element);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_manager_addr) == 0 ||
                   strcmp(node[j]->element, xml_port) == 0 ||
                   strcmp(node[j]->element, xml_interface) == 0 ||
                   strcmp(node[j]->element, xml_ssl_cipher) == 0 ||
                   strcmp(node[j]->element, xml_server_ca_path) == 0 ||
                   strcmp(node[j]->element, xml_agent_certif_path) == 0 ||
                   strcmp(node[j]->element, xml_agent_key_path) == 0) {
            minfo("<%s> under <enrollment> is no longer used: enrollment reuses "
                  "<agent><manager>/<agent><ssl>. Ignoring.", node[j]->element);
        } else {
            merror(XML_INVELEM, node[j]->element);
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
                free(config->server[i].endpoint);
            }

            free(config->server);
        }

        free(config->profile);

        os_free(config->ssl.certificate);
        os_free(config->ssl.key);
        os_free(config->ssl.certificate_authorities);
        os_free(config->ssl.ciphers);

        os_free(config->enrollment.agent_name);
        os_free(config->enrollment.groups);
        os_free(config->enrollment.agent_address);
        os_free(config->enrollment.authorization_pass_path);
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
        /* #38624: the scope now comes from <endpoint>'s IPv6 zone id rather than the
         * removed <interface_index> tag, but the check is the same one -- a link-local
         * address without a scope is ambiguous and cannot be dialed reliably. */
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
                (strncmp(ip_address, IPV6_LINK_LOCAL_PREFIX, 20) == 0 && servers[i].scope_id > 0)) {
                os_free(ip_address);
                ret = true;
                continue;
            }
            else if ((strncmp(ip_address, IPV6_LINK_LOCAL_PREFIX, 20) == 0 && servers[i].scope_id == 0)) {
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
