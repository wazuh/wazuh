/*
 * Authd settings manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 29, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "os_err.h"
#include "os_xml.h"
#include "shared.h"
#include "authd-config.h"
#include "config.h"
#include "ssl_op.h"
#include <string.h>

#ifndef WIN32

#ifdef WAZUH_UNIT_TESTING
// Remove STATIC qualifier from tests
#define STATIC
#else
#define STATIC static
#endif

/* TLS 1.3 ciphersuite names accepted by SSL_CTX_set_ciphersuites() (RFC 8446 section B.4) */
static const char *VALID_TLS13_CIPHERSUITES[] = {
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_CHACHA20_POLY1305_SHA256",
    "TLS_AES_128_CCM_SHA256",
    "TLS_AES_128_CCM_8_SHA256",
    NULL
};

int w_authd_validate_ciphers(const char *ciphers) {
    if (!ciphers || !*ciphers) {
        return OS_INVALID;
    }

    char *copy = strdup(ciphers);
    char *token = strtok(copy, ":");
    int result = 0;
    int token_seen = 0;

    while (token) {
        token_seen = 1;
        int valid = 0;

        for (int i = 0; VALID_TLS13_CIPHERSUITES[i]; i++) {
            if (!strcmp(token, VALID_TLS13_CIPHERSUITES[i])) {
                valid = 1;
                break;
            }
        }

        if (!valid) {
            merror("Invalid TLS 1.3 cipher suite '%s' in 'ciphers' option", token);
            result = OS_INVALID;
            break;
        }

        token = strtok(NULL, ":");
    }

    if (!token_seen) {
        merror("Invalid TLS 1.3 cipher suite list: '%s'", ciphers);
        result = OS_INVALID;
    }

    free(copy);
    return result;
}

int get_time_interval(char *source, time_t *interval) {
    char *endptr;
    *interval = strtoul(source, &endptr, 0);

    if ((!*interval && endptr == source) || *interval < 0) {
        return OS_INVALID;
    }

    switch (*endptr) {
    case 'd':
        *interval *= 86400;
        break;
    case 'h':
        *interval *= 3600;
        break;
    case 'm':
        *interval *= 60;
        break;
    case 's':
    case '\0':
        break;
    default:
        return OS_INVALID;
    }

    return 0;
}

#ifndef CLIENT
#include "mconf-config.h"

/* Defaults of the `auth` section, applied before reading the JSON keys. */
static void w_authd_json_defaults(authd_config_t *config) {
    /* flags.disabled is left alone on purpose: it is a plain 0/1 flag. The caller's authd_config_t
     * starts zeroed (authd enabled) and only <disabled>/`disabled` ever writes it. */
    config->port = 1515;
    config->flags.use_source_ip = 0;
    config->flags.clear_removed = 0;
    config->flags.use_password = 0;
    os_free(config->ciphers);
    config->ciphers = strdup(DEFAULT_CIPHERS);
    config->flags.verify_host = 0;
    os_free(config->manager_cert);
    config->manager_cert = strdup("etc/certs/remoted.pem");
    os_free(config->manager_key);
    config->manager_key = strdup("etc/certs/remoted-key.pem");
    config->flags.remote_enrollment = 1;
    config->flags.legacy_enrollment = 1;
    config->force_options.enabled = true;
    config->force_options.key_mismatch = true;
    config->force_options.disconnected_time_enabled = true;
    config->force_options.disconnected_time = 3600;
    config->force_options.after_registration_time = 3600;
}

/* String option: absent keeps the default, empty means "unset" (NULL), anything else is copied. */
static void w_authd_json_string(const cJSON *auth, const char *key, char **dest) {
    const cJSON *item = cJSON_GetObjectItem(auth, key);

    if (!cJSON_IsString(item) || item->valuestring == NULL) {
        return;
    }

    os_free(*dest);
    if (item->valuestring[0] != '\0') {
        os_strdup(item->valuestring, *dest);
    }
}

/* Duration option (integer seconds or "<n>[smhdw]"); absent keeps the default. */
static int w_authd_json_time(const cJSON *object, const char *key, time_t *dest) {
    const cJSON *item = cJSON_GetObjectItem(object, key);
    long value;

    if (item == NULL) {
        return OS_SUCCESS;
    }

    value = w_mconf_json_time(item);
    if (value < 0) {
        merror("Invalid interval for '%s' option", key);
        return OS_INVALID;
    }

    *dest = (time_t) value;
    return OS_SUCCESS;
}

/* Reader of the `auth` section of the effective document (mconf-config.h): same struct and
 * defaults the XML reader used to apply; shared by wazuh-manager-authd and by remoted's enrollment bridge. */
int Read_Authd_JSON(const struct cJSON *auth, void *d1) {
    authd_config_t *config = (authd_config_t *)d1;
    const cJSON *item = NULL;
    const cJSON *force = NULL;
    const cJSON *agents = NULL;

    if (config == NULL) {
        return OS_INVALID;
    }

    w_authd_json_defaults(config);

    if (auth == NULL) {
        return 0;
    }

    if (item = cJSON_GetObjectItem(auth, "disabled"), cJSON_IsBool(item)) {
        config->flags.disabled = cJSON_IsTrue(item) ? 1 : 0;
    }

    if (item = cJSON_GetObjectItem(auth, "port"), cJSON_IsNumber(item)) {
        config->port = (unsigned short) item->valueint;

        if (!config->port) {
            w_mconf_json_invalid("port", item);
            return OS_INVALID;
        }
    }

    config->ipv6 = w_mconf_json_bool(cJSON_GetObjectItem(auth, "ipv6"), config->ipv6) != 0;
    config->flags.use_source_ip = w_mconf_json_bool(cJSON_GetObjectItem(auth, "use_source_ip"), config->flags.use_source_ip);
    config->flags.clear_removed = w_mconf_json_bool(cJSON_GetObjectItem(auth, "purge"), config->flags.clear_removed);
    config->flags.use_password = w_mconf_json_bool(cJSON_GetObjectItem(auth, "use_password"), config->flags.use_password);
    config->flags.remote_enrollment = w_mconf_json_bool(cJSON_GetObjectItem(auth, "remote_enrollment"), config->flags.remote_enrollment);
    config->flags.legacy_enrollment = w_mconf_json_bool(cJSON_GetObjectItem(auth, "legacy_enrollment"), config->flags.legacy_enrollment);
    config->flags.verify_host = w_mconf_json_bool(cJSON_GetObjectItem(auth, "ssl_verify_host"), config->flags.verify_host);

    if (item = cJSON_GetObjectItem(auth, "ciphers"), cJSON_IsString(item) && item->valuestring != NULL && item->valuestring[0] != '\0') {
        if (w_authd_validate_ciphers(item->valuestring) == OS_INVALID) {
            return OS_INVALID;
        }
        os_free(config->ciphers);
        os_strdup(item->valuestring, config->ciphers);
    }

    w_authd_json_string(auth, "ssl_agent_ca", &config->agent_ca);
    w_authd_json_string(auth, "ssl_manager_cert", &config->manager_cert);
    w_authd_json_string(auth, "ssl_manager_key", &config->manager_key);

    if (force = cJSON_GetObjectItem(auth, "force"), cJSON_IsObject(force)) {
        const cJSON *disconnected = cJSON_GetObjectItem(force, "disconnected_time");

        config->force_options.enabled = w_mconf_json_bool(cJSON_GetObjectItem(force, "enabled"), config->force_options.enabled) != 0;
        config->force_options.key_mismatch = w_mconf_json_bool(cJSON_GetObjectItem(force, "key_mismatch"), config->force_options.key_mismatch) != 0;

        if (cJSON_IsObject(disconnected)) {
            config->force_options.disconnected_time_enabled =
                w_mconf_json_bool(cJSON_GetObjectItem(disconnected, "enabled"), config->force_options.disconnected_time_enabled) != 0;
            if (w_authd_json_time(disconnected, "value", &config->force_options.disconnected_time) == OS_INVALID) {
                return OS_INVALID;
            }
        }

        if (w_authd_json_time(force, "after_registration_time", &config->force_options.after_registration_time) == OS_INVALID) {
            return OS_INVALID;
        }
    }

    if (agents = cJSON_GetObjectItem(auth, "agents"), cJSON_IsObject(agents)) {
        config->allow_higher_versions =
            w_mconf_json_bool(cJSON_GetObjectItem(agents, "allow_higher_versions"), config->allow_higher_versions) != 0;
    }

    return 0;
}
#endif /* CLIENT */

#endif
