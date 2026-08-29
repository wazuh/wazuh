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
 * @brief rejects a remote.https string option that would overflow the fixed-size
 *        C-ABI buffer it's later copied into by secure.c's HandleSecure(), instead of
 *        letting it be silently truncated by snprintf
 *
 * @param element option name, for the error message
 * @param content configuration string to check
 * @param max_len maximum accepted length (buffer size minus 1, for the NUL terminator)
 * @return OS_SUCCESS if content fits, OS_INVALID (with a merror already logged) otherwise
 */
STATIC int w_remoted_https_check_max_len(const char * element, const char * content, size_t max_len);

/**
 * @brief validates remote.https.ciphers as a TLS 1.3 suite list, so 'remoted -t' rejects a
 *        TLS 1.2 string instead of the HTTPS server failing to start at runtime.
 *
 * @param ciphers raw ciphers value
 * @return OS_SUCCESS when every element is a known suite, OS_INVALID otherwise
 */
STATIC int w_remoted_validate_tls13_ciphers(const char * ciphers);

/**
 * @brief validates remote.https.global_prefix as a URL path prefix, so 'remoted -t'
 *        rejects a bad value instead of the HTTPS server refusing to start at runtime.
 *
 * Accepted grammar: '/' alone (explicit identity: endpoints served unprefixed), or
 * '/segment[/segment...]' with an optional trailing '/'. Every byte must be in
 * [A-Za-z0-9._~/-] (RFC 3986 unreserved plus '/'): deliberately no '%' -- the prefix is
 * compared byte-exactly against the wire target, never percent-decoded -- and no '?', '#',
 * whitespace or other URL-hostile characters. Empty segments ('//') and '.'/'..' segments are
 * rejected: proxies dot-normalize request paths, so such a prefix could never match
 * consistently. Length is checked separately (w_remoted_https_check_max_len).
 *
 * @param prefix raw global_prefix value
 * @return OS_SUCCESS when the value is a usable prefix, OS_INVALID otherwise
 */
STATIC int w_remoted_validate_global_prefix(const char * prefix);

STATIC int w_remoted_https_check_max_len(const char * element, const char * content, size_t max_len) {
    if (strlen(content) > max_len) {
        merror("Value for 'remote.https.%s' exceeds the maximum length of %zu characters.", element, max_len);
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
        merror("Invalid 'remote.https.ciphers' option: expected TLS 1.3 cipher suite names.");
        return (OS_INVALID);
    }

    // Hand-walked, not strtok: strtok collapses separators, so ':X' and 'X::Y' would wrongly pass.
    const char * element = ciphers;

    for (;;) {
        const char * separator = strchr(element, ':');
        const size_t length = separator ? (size_t)(separator - element) : strlen(element);

        if (length == 0) {
            merror("Invalid 'remote.https.ciphers' option: '%s' has an empty cipher suite name.", ciphers);
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
            merror("Invalid TLS 1.3 cipher suite '%.*s' in the 'remote.https.ciphers' option.", (int)length, element);
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
        merror("Invalid 'remote.https.global_prefix' option: the value cannot be empty.");
        return (OS_INVALID);
    }

    if (prefix[0] != '/') {
        merror("Invalid 'remote.https.global_prefix' option: '%s' must start with '/'.", prefix);
        return (OS_INVALID);
    }

    for (const char * p = prefix; *p; p++) {
        const char c = *p;
        const int allowed = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                            c == '.' || c == '_' || c == '~' || c == '-' || c == '/';

        if (!allowed) {
            merror("Invalid character '%c' in the 'remote.https.global_prefix' option: allowed characters are "
                   "A-Z, a-z, 0-9, '.', '_', '~', '-' and '/'.", c);
            return (OS_INVALID);
        }
    }

    if (strstr(prefix, "//") != NULL) {
        merror("Invalid 'remote.https.global_prefix' option: '%s' contains an empty path segment ('//').", prefix);
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
            merror("Invalid 'remote.https.global_prefix' option: '%s' contains a '.' or '..' path segment.", prefix);
            return (OS_INVALID);
        }

        if (!separator) {
            break;
        }

        segment = separator + 1;
    }

    return OS_SUCCESS;
}

#ifndef CLIENT
#include "mconf-config.h"

/* String option of remote.https from the effective document: absent or empty keeps the module
 * default (NULL) and returns 0; otherwise the same length limit the XML reader enforces, then the
 * optional per-option validator, then the copy. Returns 1 when a value was stored, OS_INVALID on error. */
static int w_remoted_json_https_string(const cJSON *https, const char *key, size_t max_len,
                                       int (*validate)(const char *), char **dest) {
    const cJSON *item = cJSON_GetObjectItem(https, key);

    if (!cJSON_IsString(item) || item->valuestring == NULL || item->valuestring[0] == '\0') {
        return 0;
    }

    if (w_remoted_https_check_max_len(key, item->valuestring, max_len) == OS_INVALID) {
        return (OS_INVALID);
    }

    if (validate != NULL && validate(item->valuestring) == OS_INVALID) {
        return (OS_INVALID);
    }

    os_free(*dest);
    os_strdup(item->valuestring, *dest);
    return 1;
}

/* OS_IsValidIP() as a plain string validator for w_remoted_json_https_string(). */
static int w_remoted_json_valid_ip(const char *address) {
    if (OS_IsValidIP(address, NULL) != 1) {
        merror(INVALID_IP, address);
        return (OS_INVALID);
    }
    return OS_SUCCESS;
}

/* Reader of the `remote` section of the effective YAML document (mconf-config.h): same struct, same
 * defaults and the same inferences the XML reader used to apply; types and ranges come guaranteed by the schema, so only
 * the checks the schema cannot express (lengths, IPs, prefix segments, cipher names) are repeated. */
int Read_Remote_JSON(const struct cJSON *remote, void *d1)
{
    remoted *logr = (remoted *)d1;
    const cJSON *legacy = NULL;
    const cJSON *https = NULL;
    const cJSON *agents = NULL;
    const cJSON *item = NULL;

    if (logr == NULL) {
        return (OS_INVALID);
    }

    if (remote != NULL) {
        legacy = cJSON_GetObjectItem(remote, "legacy");
        https = cJSON_GetObjectItem(remote, "https");
        agents = cJSON_GetObjectItem(remote, "agents");
    }

    /* legacy: the effective document always carries the block; `enabled: false` is how the schema
     * represents a disabled legacy listener. */
    logr->legacy_enabled = false;

    if (cJSON_IsObject(legacy)) {
        logr->legacy_enabled = w_mconf_json_bool(cJSON_GetObjectItem(legacy, "enabled"), 1) != 0;
        os_free(logr->lip);
        logr->rids_closing_time = REMOTED_RIDS_CLOSING_TIME_DEFAULT;

        if (item = cJSON_GetObjectItem(legacy, "port"), cJSON_IsNumber(item)) {
            logr->port = item->valueint;

            if (logr->port <= 0 || logr->port > 65535) {
                merror(PORT_ERROR, logr->port);
                return (OS_INVALID);
            }
        }

        if (item = cJSON_GetObjectItem(legacy, "protocol"), cJSON_IsArray(item)) {
            const cJSON *word = NULL;
            int proto = 0;

            cJSON_ArrayForEach(word, item) {
                if (!cJSON_IsString(word) || word->valuestring == NULL) {
                    continue;
                }
                if (strcasecmp(word->valuestring, REMOTED_NET_PROTOCOL_TCP_STR) == 0) {
                    proto |= REMOTED_NET_PROTOCOL_TCP;
                } else if (strcasecmp(word->valuestring, REMOTED_NET_PROTOCOL_UDP_STR) == 0) {
                    proto |= REMOTED_NET_PROTOCOL_UDP;
                } else {
                    mwarn(REMOTED_INV_VALUE_IGNORE, word->valuestring, "protocol");
                }
            }

            if (proto == 0) {
                mwarn(REMOTED_NET_PROTOCOL_ERROR, REMOTED_NET_PROTOCOL_DEFAULT_STR);
                proto = REMOTED_NET_PROTOCOL_DEFAULT;
            }
            logr->proto = proto;
        }

        logr->ipv6 = w_mconf_json_bool(cJSON_GetObjectItem(legacy, "ipv6"), logr->ipv6);

        if (item = cJSON_GetObjectItem(legacy, "local_ip"),
            cJSON_IsString(item) && item->valuestring != NULL && item->valuestring[0] != '\0') {
            os_strdup(item->valuestring, logr->lip);

            if (OS_IsValidIP(logr->lip, NULL) != 1) {
                merror(INVALID_IP, item->valuestring);
                return (OS_INVALID);
            } else if (strchr(logr->lip, ':') != NULL) {
                os_realloc(logr->lip, IPSIZE + 1, logr->lip);
                OS_ExpandIPv6(logr->lip, IPSIZE);
            }
        }

        if (item = cJSON_GetObjectItem(legacy, "queue_size"), cJSON_IsNumber(item)) {
            if (item->valuedouble < 1) {
                merror("Invalid value for option 'queue_size'");
                return (OS_INVALID);
            }
            logr->queue_size = (long) item->valuedouble;
        }

        if (item = cJSON_GetObjectItem(legacy, "rids_closing_time"), item != NULL) {
            long rids_closing_time = w_mconf_json_time(item);

            if (rids_closing_time <= 0 || rids_closing_time > INT_MAX) {
                char *text = cJSON_PrintUnformatted(item);
                mwarn(REMOTED_INV_VALUE_DEFAULT, text != NULL ? text : "", "rids_closing_time");
                free(text);
                rids_closing_time = REMOTED_RIDS_CLOSING_TIME_DEFAULT;
            }
            logr->rids_closing_time = (int) rids_closing_time;
        }

        if (item = cJSON_GetObjectItem(legacy, "connection_overtake_time"), cJSON_IsNumber(item)) {
            if (item->valueint < 0 || item->valueint > 3600) {
                mwarn("Invalid value for element '%s':'%d'. Setting to default value: '%d'.",
                      "connection_overtake_time", item->valueint, logr->connection_overtake_time);
            } else {
                logr->connection_overtake_time = item->valueint;
            }
        }
    }

    /* https */
    if (cJSON_IsObject(https)) {
        if (item = cJSON_GetObjectItem(https, "port"), cJSON_IsNumber(item)) {
            logr->https.port = item->valueint;

            if (logr->https.port <= 0 || logr->https.port > 65535) {
                merror(PORT_ERROR, logr->https.port);
                return (OS_INVALID);
            }
        }

        if (w_remoted_json_https_string(https, "bind_addr", REMOTED_HTTPS_BIND_ADDR_MAX_LEN, w_remoted_json_valid_ip, &logr->https.bind_addr) == OS_INVALID ||
            w_remoted_json_https_string(https, "global_prefix", REMOTED_HTTPS_GLOBAL_PREFIX_MAX_LEN, w_remoted_validate_global_prefix, &logr->https.global_prefix) == OS_INVALID ||
            w_remoted_json_https_string(https, "certificate", REMOTED_HTTPS_CERTIFICATE_MAX_LEN, NULL, &logr->https.certificate) == OS_INVALID ||
            w_remoted_json_https_string(https, "key", REMOTED_HTTPS_KEY_MAX_LEN, NULL, &logr->https.key) == OS_INVALID ||
            w_remoted_json_https_string(https, "ca", REMOTED_HTTPS_CA_MAX_LEN, NULL, &logr->https.ca) == OS_INVALID) {
            return (OS_INVALID);
        }

        if (item = cJSON_GetObjectItem(https, "verification_mode"), cJSON_IsString(item) && item->valuestring != NULL) {
            if (strcasecmp(item->valuestring, "none") == 0) {
                logr->https.verification_mode = REMOTED_HTTPS_VERIFY_NONE;
            } else if (strcasecmp(item->valuestring, "certificate") == 0) {
                logr->https.verification_mode = REMOTED_HTTPS_VERIFY_CERTIFICATE;
            } else if (strcasecmp(item->valuestring, "full") == 0) {
                logr->https.verification_mode = REMOTED_HTTPS_VERIFY_FULL;
            } else {
                // Reject, don't fall back: a typo must not silently disable certificate verification.
                w_mconf_json_invalid("verification_mode", item);
                return (OS_INVALID);
            }
        }

        if (w_remoted_json_https_string(https, "ciphers", REMOTED_HTTPS_CIPHERS_MAX_LEN, w_remoted_validate_tls13_ciphers, &logr->https.ciphers) == OS_INVALID) {
            return (OS_INVALID);
        }

        if (item = cJSON_GetObjectItem(https, "max_body_size"), item != NULL) {
            long max_body_size = w_mconf_json_size(item);

            if (max_body_size <= 0) {
                w_mconf_json_invalid("max_body_size", item);
                return (OS_INVALID);
            }
            logr->https.max_body_size = max_body_size;
        }

        if (item = cJSON_GetObjectItem(https, "dual_stack"), cJSON_IsBool(item)) {
            logr->https.dual_stack = cJSON_IsTrue(item) ? REMOTED_HTTPS_DUAL_STACK_YES : REMOTED_HTTPS_DUAL_STACK_NO;
        }
    }

    /* agents */
    if (cJSON_IsObject(agents)) {
        logr->allow_higher_versions =
            w_mconf_json_bool(cJSON_GetObjectItem(agents, "allow_higher_versions"), logr->allow_higher_versions) != 0;
    }

    /* Closing rules: the classic listener keeps its disabled state (0/NULL)
     * unless legacy.enabled is true. */
    if (logr->legacy_enabled) {
        if (logr->port == 0) {
            logr->port = DEFAULT_REMOTE_PORT;
        }
        if (logr->proto == 0) {
            logr->proto = REMOTED_NET_PROTOCOL_DEFAULT;
        }
        if (logr->lip == NULL && !logr->ipv6) {
            os_strdup(REMOTED_LEGACY_LOCAL_IP_DEFAULT, logr->lip);
        }
    } else {
        logr->port = 0;
        logr->proto = 0;
        os_free(logr->lip);
    }

    // Inferences: a configured CA without a verification mode means
    // certificate-chain verification; dual_stack only applies to an IPv6 bind_addr.
    if (logr->https.ca != NULL && logr->https.verification_mode == REMOTED_HTTPS_VERIFY_UNSET) {
        mwarn("The 'remote.https.ca' option is configured but 'verification_mode' is not; "
              "defaulting 'verification_mode' to 'certificate'.");
        logr->https.verification_mode = REMOTED_HTTPS_VERIFY_CERTIFICATE;
    }

    if (logr->https.dual_stack != REMOTED_HTTPS_DUAL_STACK_UNSET &&
        (logr->https.bind_addr == NULL || strchr(logr->https.bind_addr, ':') == NULL)) {
        mwarn("The 'remote.https.dual_stack' option only applies to an IPv6 'bind_addr'; ignoring it.");
    }

    return (0);
}
#endif /* CLIENT */
