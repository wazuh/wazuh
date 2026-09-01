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

/**
 * @brief parses the <remote><legacy> block (classic TCP/UDP listener options)
 *
 * @param node XML node
 * @param logr remoted configuration structure
 * @return OS_SUCCESS on success, OS_INVALID on a fatal parsing error
 */
STATIC int w_remoted_parse_legacy(XML_NODE node, remoted * logr);

/**
 * @brief parses the <remote><https> block (RESTinio HTTPS server options)
 *
 * @param node XML node
 * @param logr remoted configuration structure
 * @return OS_SUCCESS on success, OS_INVALID on a fatal parsing error
 */
STATIC int w_remoted_parse_https(XML_NODE node, remoted * logr);

/**
 * @brief rejects a <remote><https> string option that would overflow the fixed-size
 *        C-ABI buffer it's later copied into by secure.c's HandleSecure(), instead of
 *        letting it be silently truncated by snprintf
 *
 * @param element XML element name, for the error message
 * @param content configuration string to check
 * @param max_len maximum accepted length (buffer size minus 1, for the NUL terminator)
 * @return OS_SUCCESS if content fits, OS_INVALID (with a merror already logged) otherwise
 */
STATIC int w_remoted_https_check_max_len(const char * element, const char * content, size_t max_len);

/**
 * @brief validates <remote><https><ciphers> as a TLS 1.3 suite list, so 'remoted -t' rejects a
 *        TLS 1.2 string instead of the HTTPS server failing to start at runtime.
 *
 * @param ciphers raw <ciphers> content
 * @return OS_SUCCESS when every element is a known suite, OS_INVALID otherwise
 */
STATIC int w_remoted_validate_tls13_ciphers(const char * ciphers);

/**
 * @brief validates <remote><https><global_prefix> as a URL path prefix, so 'remoted -t'
 *        rejects a bad value instead of the HTTPS server refusing to start at runtime.
 *
 * Accepted grammar: '/' alone (explicit identity: endpoints served unprefixed), or
 * '/segment[/segment...]' with an optional trailing '/'. Every byte must be in
 * [A-Za-z0-9._~/-] (RFC 3986 unreserved plus '/'): deliberately no '%' -- the prefix is
 * compared byte-exactly against the wire target, never percent-decoded -- and no '?', '#',
 * whitespace or XML-hostile characters. Empty segments ('//') and '.'/'..' segments are
 * rejected: proxies dot-normalize request paths, so such a prefix could never match
 * consistently. Length is checked separately (w_remoted_https_check_max_len).
 *
 * @param prefix raw <global_prefix> content
 * @return OS_SUCCESS when the value is a usable prefix, OS_INVALID otherwise
 */
STATIC int w_remoted_validate_global_prefix(const char * prefix);

/* Reads remote config */
int Read_Remote(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;
    remoted * logr = NULL;

    /*** XML Definitions ***/
    const char *xml_remote_https = "https";
    const char *xml_remote_legacy = "legacy";
    const char *xml_remote_agents = "agents";

    logr = (remoted *)d1;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcasecmp(node[i]->element, xml_remote_legacy) == 0) {
            logr->legacy_enabled = true;
            xml_node **children = OS_GetElementsbyNode(xml, node[i]);
            if (children != NULL) {
                int ret = w_remoted_parse_legacy(children, logr);
                OS_ClearNode(children);
                if (ret == OS_INVALID) {
                    return (OS_INVALID);
                }
            }
        } else if (strcasecmp(node[i]->element, xml_remote_https) == 0) {
            xml_node **children = OS_GetElementsbyNode(xml, node[i]);
            if (children != NULL) {
                int ret = w_remoted_parse_https(children, logr);
                OS_ClearNode(children);
                if (ret == OS_INVALID) {
                    return (OS_INVALID);
                }
            }
        } else if (strcasecmp(node[i]->element, xml_remote_agents) == 0) {
            xml_node **children = OS_GetElementsbyNode(xml, node[i]);
            if (children != NULL) {
                w_remoted_parse_agents(children, logr);
                OS_ClearNode(children);
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    /* These settings only make sense for the classic listener; keeping them at their
     * disabled state (0/NULL) when <legacy> is absent or disabled is what keeps
     * HandleRemote() from binding it and secure.c's protocol-gated wnotify_add() from
     * touching a socket that was never bound. */
    if (logr->legacy_enabled) {
        /* Set port in here */
        if (logr->port == 0) {
            logr->port = DEFAULT_REMOTE_PORT;
        }

        /* Set protocol in here */
        if (logr->proto == 0) {
            logr->proto = REMOTED_NET_PROTOCOL_DEFAULT;
        }

        /* Set local ip in here */
        if (logr->lip == NULL && !logr->ipv6) {
            os_strdup(REMOTED_LEGACY_LOCAL_IP_DEFAULT, logr->lip);
        }
    } else {
        logr->port = 0;
        logr->proto = 0;
        os_free(logr->lip);
    }

    return (0);
}

STATIC int w_remoted_parse_legacy(XML_NODE node, remoted * logr) {
    const char *xml_remote_port = "port";
    const char *xml_remote_proto = "protocol";
    const char *xml_remote_ipv6 = "ipv6";
    const char *xml_remote_lip = "local_ip";
    const char *xml_queue_size = "queue_size";
    const char *xml_rids_closing_time = "rids_closing_time";
    const char *xml_connection_overtake_time = "connection_overtake_time";
    const char *xml_remote_enabled = "enabled";

    int i = 0;

    logr->lip = NULL;
    logr->rids_closing_time = REMOTED_RIDS_CLOSING_TIME_DEFAULT;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcasecmp(node[i]->element, xml_remote_port) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->port = atoi(node[i]->content);

            if (logr->port <= 0 || logr->port > 65535) {
                merror(PORT_ERROR, logr->port);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_proto) == 0) {

            logr->proto = w_remoted_get_net_protocol(node[i]->content);

        } else if (strcasecmp(node[i]->element, xml_remote_ipv6) == 0) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                logr->ipv6 = 1;
            } else if (strcasecmp(node[i]->content, "no") == 0) {
                logr->ipv6 = 0;
            } else {
                mwarn(REMOTED_INV_VALUE_IGNORE, node[i]->content, xml_remote_ipv6);
            }
        } else if (strcasecmp(node[i]->element, xml_remote_lip) == 0) {
            os_strdup(node[i]->content, logr->lip);
            if (OS_IsValidIP(logr->lip, NULL) != 1) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            } else if (strchr(logr->lip, ':') != NULL) {
                os_realloc(logr->lip, IPSIZE + 1, logr->lip);
                OS_ExpandIPv6(logr->lip, IPSIZE);
            }
        }
        else if (strcmp(node[i]->element, xml_queue_size) == 0) {
            char * end;

            logr->queue_size = strtol(node[i]->content, &end, 10);

            if (*end != '\0' || logr->queue_size < 1) {
                merror("Invalid value for option '<%s>'", xml_queue_size);
                return OS_INVALID;
            }

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
        } else if (strcasecmp(node[i]->element, xml_remote_enabled) == 0) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                logr->legacy_enabled = true;
            } else if (strcasecmp(node[i]->content, "no") == 0) {
                logr->legacy_enabled = false;
            } else {
                mwarn(REMOTED_INV_VALUE_IGNORE, node[i]->content, xml_remote_enabled);
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    return OS_SUCCESS;
}

STATIC int w_remoted_parse_https(XML_NODE node, remoted * logr) {
    const char *xml_https_port = "port";
    const char *xml_https_bind_addr = "bind_addr";
    const char *xml_https_global_prefix = "global_prefix";
    const char *xml_https_certificate = "certificate";
    const char *xml_https_key = "key";
    const char *xml_https_ca = "ca";
    const char *xml_https_verification_mode = "verification_mode";
    const char *xml_https_ciphers = "ciphers";
    const char *xml_https_max_body_size = "max_body_size";
    const char *xml_https_dual_stack = "dual_stack";

    int i = 0;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcasecmp(node[i]->element, xml_https_port) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->https.port = atoi(node[i]->content);

            if (logr->https.port <= 0 || logr->https.port > 65535) {
                merror(PORT_ERROR, logr->https.port);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_https_bind_addr) == 0) {
            if (w_remoted_https_check_max_len(xml_https_bind_addr, node[i]->content, REMOTED_HTTPS_BIND_ADDR_MAX_LEN) == OS_INVALID) {
                return (OS_INVALID);
            }

            os_free(logr->https.bind_addr);
            os_strdup(node[i]->content, logr->https.bind_addr);

            if (OS_IsValidIP(logr->https.bind_addr, NULL) != 1) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_https_global_prefix) == 0) {
            if (w_remoted_https_check_max_len(xml_https_global_prefix, node[i]->content, REMOTED_HTTPS_GLOBAL_PREFIX_MAX_LEN) == OS_INVALID) {
                return (OS_INVALID);
            }

            if (w_remoted_validate_global_prefix(node[i]->content) == OS_INVALID) {
                return (OS_INVALID);
            }

            os_free(logr->https.global_prefix);
            os_strdup(node[i]->content, logr->https.global_prefix);
        } else if (strcasecmp(node[i]->element, xml_https_certificate) == 0) {
            if (w_remoted_https_check_max_len(xml_https_certificate, node[i]->content, REMOTED_HTTPS_CERTIFICATE_MAX_LEN) == OS_INVALID) {
                return (OS_INVALID);
            }

            os_free(logr->https.certificate);
            os_strdup(node[i]->content, logr->https.certificate);
        } else if (strcasecmp(node[i]->element, xml_https_key) == 0) {
            if (w_remoted_https_check_max_len(xml_https_key, node[i]->content, REMOTED_HTTPS_KEY_MAX_LEN) == OS_INVALID) {
                return (OS_INVALID);
            }

            os_free(logr->https.key);
            os_strdup(node[i]->content, logr->https.key);
        } else if (strcasecmp(node[i]->element, xml_https_ca) == 0) {
            if (w_remoted_https_check_max_len(xml_https_ca, node[i]->content, REMOTED_HTTPS_CA_MAX_LEN) == OS_INVALID) {
                return (OS_INVALID);
            }

            os_free(logr->https.ca);
            os_strdup(node[i]->content, logr->https.ca);
        } else if (strcasecmp(node[i]->element, xml_https_verification_mode) == 0) {
            if (strcasecmp(node[i]->content, "none") == 0) {
                logr->https.verification_mode = REMOTED_HTTPS_VERIFY_NONE;
            } else if (strcasecmp(node[i]->content, "certificate") == 0) {
                logr->https.verification_mode = REMOTED_HTTPS_VERIFY_CERTIFICATE;
            } else if (strcasecmp(node[i]->content, "full") == 0) {
                logr->https.verification_mode = REMOTED_HTTPS_VERIFY_FULL;
            } else {
                // Reject, don't fall back: a typo must not silently disable certificate verification.
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcasecmp(node[i]->element, xml_https_ciphers) == 0) {
            if (w_remoted_https_check_max_len(xml_https_ciphers, node[i]->content, REMOTED_HTTPS_CIPHERS_MAX_LEN) == OS_INVALID) {
                return (OS_INVALID);
            }

            if (w_remoted_validate_tls13_ciphers(node[i]->content) == OS_INVALID) {
                return (OS_INVALID);
            }

            os_free(logr->https.ciphers);
            os_strdup(node[i]->content, logr->https.ciphers);
        } else if (strcasecmp(node[i]->element, xml_https_max_body_size) == 0) {
            ssize_t max_body_size = w_parse_size(node[i]->content);

            if (max_body_size <= 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            logr->https.max_body_size = (long) max_body_size;
        } else if (strcasecmp(node[i]->element, xml_https_dual_stack) == 0) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                logr->https.dual_stack = REMOTED_HTTPS_DUAL_STACK_YES;
            } else if (strcasecmp(node[i]->content, "no") == 0) {
                logr->https.dual_stack = REMOTED_HTTPS_DUAL_STACK_NO;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }

    // The operator explicitly configured <ca> in XML but never said what to do with it
    // (<verification_mode> was left untouched): infer they want certificate-chain
    // verification rather than silently leaving client-certificate verification
    // disabled. An explicit <verification_mode> (even "none") always wins over this
    // inference -- this only fires when verification_mode is still REMOTED_HTTPS_VERIFY_UNSET.
    if (logr->https.ca != NULL && logr->https.verification_mode == REMOTED_HTTPS_VERIFY_UNSET) {
        mwarn("The '<remote><https><ca>' option is configured but '<verification_mode>' is not; "
              "defaulting '<verification_mode>' to 'certificate'.");
        logr->https.verification_mode = REMOTED_HTTPS_VERIFY_CERTIFICATE;
    }

    // dual_stack only affects the IPV6_V6ONLY socket option, which only applies to an
    // IPv6 socket; an IPv4 bind_addr (including the "unset -> module default" case,
    // which defaults to IPv4) makes it a no-op, so just warn instead of failing.
    if (logr->https.dual_stack != REMOTED_HTTPS_DUAL_STACK_UNSET &&
        (logr->https.bind_addr == NULL || strchr(logr->https.bind_addr, ':') == NULL)) {
        mwarn("The '<remote><https><dual_stack>' option only applies to an IPv6 'bind_addr'; ignoring it.");
    }

    return OS_SUCCESS;
}

STATIC int w_remoted_https_check_max_len(const char * element, const char * content, size_t max_len) {
    if (strlen(content) > max_len) {
        merror("Value for '<remote><https><%s>' exceeds the maximum length of %zu characters.", element, max_len);
        return (OS_INVALID);
    }

    return OS_SUCCESS;
}

STATIC int w_remoted_validate_tls13_ciphers(const char * ciphers) {
    // Same TLS 1.3 suite names OpenSSL's SSL_CTX_set_ciphersuites() accepts (RFC 8446 section B.4).
    static const char * VALID_TLS13_CIPHERSUITES[] = {
        "TLS_AES_128_GCM_SHA256",
        "TLS_AES_256_GCM_SHA384",
        "TLS_CHACHA20_POLY1305_SHA256",
        "TLS_AES_128_CCM_SHA256",
        "TLS_AES_128_CCM_8_SHA256",
        NULL
    };

    if (ciphers == NULL || *ciphers == '\0') {
        merror("Invalid '<remote><https><ciphers>' option: expected TLS 1.3 cipher suite names.");
        return (OS_INVALID);
    }

    // Hand-walked, not strtok: strtok collapses separators, so ':X' and 'X::Y' would wrongly pass.
    const char * element = ciphers;

    for (;;) {
        const char * separator = strchr(element, ':');
        const size_t length = separator ? (size_t)(separator - element) : strlen(element);

        if (length == 0) {
            merror("Invalid '<remote><https><ciphers>' option: '%s' has an empty cipher suite name.", ciphers);
            return (OS_INVALID);
        }

        int valid = 0;
        for (int i = 0; VALID_TLS13_CIPHERSUITES[i]; i++) {
            if (strlen(VALID_TLS13_CIPHERSUITES[i]) == length &&
                strncmp(element, VALID_TLS13_CIPHERSUITES[i], length) == 0) {
                valid = 1;
                break;
            }
        }

        if (!valid) {
            merror("Invalid TLS 1.3 cipher suite '%.*s' in the '<remote><https><ciphers>' option.", (int)length, element);
            return (OS_INVALID);
        }

        if (!separator) {
            return OS_SUCCESS;
        }

        element = separator + 1;
    }
}

STATIC int w_remoted_validate_global_prefix(const char * prefix) {
    if (prefix == NULL || *prefix == '\0') {
        merror("Invalid '<remote><https><global_prefix>' option: the value cannot be empty.");
        return (OS_INVALID);
    }

    if (prefix[0] != '/') {
        merror("Invalid '<remote><https><global_prefix>' option: '%s' must start with '/'.", prefix);
        return (OS_INVALID);
    }

    for (const char * p = prefix; *p; p++) {
        const char c = *p;
        const int allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                            c == '.' || c == '_' || c == '~' || c == '-' || c == '/';

        if (!allowed) {
            merror("Invalid character '%c' in the '<remote><https><global_prefix>' option: allowed characters are "
                   "A-Z, a-z, 0-9, '.', '_', '~', '-' and '/'.", c);
            return (OS_INVALID);
        }
    }

    if (strstr(prefix, "//") != NULL) {
        merror("Invalid '<remote><https><global_prefix>' option: '%s' contains an empty path segment ('//').", prefix);
        return (OS_INVALID);
    }

    // Walk the segments rejecting '.' and '..': proxies dot-normalize request paths, so a
    // dot-segment prefix could never match consistently. Hand-walked like the ciphers
    // validator above; the '//' rejection guarantees every segment here is non-empty.
    const char * segment = prefix + 1; // skip the leading '/'

    while (*segment) {
        const char * separator = strchr(segment, '/');
        const size_t length = separator ? (size_t)(separator - segment) : strlen(segment);

        if ((length == 1 && segment[0] == '.') || (length == 2 && segment[0] == '.' && segment[1] == '.')) {
            merror("Invalid '<remote><https><global_prefix>' option: '%s' contains a '.' or '..' path segment.", prefix);
            return (OS_INVALID);
        }

        if (!separator) {
            break;
        }

        segment = separator + 1;
    }

    return OS_SUCCESS;
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
