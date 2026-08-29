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

static short eval_bool(const char *str);
int w_read_force_config(XML_NODE node, authd_config_t *config);

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

/**
 * @brief gets the auth agents configuration
 *
 * @param node XML node
 * @param config auth configuration structure
 */
STATIC void w_authd_parse_agents(XML_NODE node, authd_config_t * config);

int Read_Authd(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2) {
    /* XML Definitions */
    static const char *xml_disabled = "disabled";
    static const char *xml_port = "port";
    static const char *xml_ipv6 = "ipv6";
    static const char *xml_use_source_ip = "use_source_ip";
    static const char *xml_force = "force";
    static const char *xml_purge = "purge";
    static const char *xml_use_password = "use_password";
    static const char *xml_ciphers = "ciphers";
    static const char *xml_ssl_agent_ca = "ssl_agent_ca";
    static const char *xml_ssl_verify_host = "ssl_verify_host";
    static const char *xml_ssl_manager_cert = "ssl_manager_cert";
    static const char *xml_ssl_manager_key = "ssl_manager_key";
    static const char *xml_remote_enrollment = "remote_enrollment";
    static const char *xml_legacy_enrollment = "legacy_enrollment";
    static const char *xml_agents = "agents";

    authd_config_t *config = (authd_config_t *)d1;
    int i;

    char manager_cert[OS_SIZE_1024];
    char manager_key[OS_SIZE_1024];

    /* Manager's unified TLS identity (see shared/include/ssl_op.h's CERTFILE/KEYFILE): authd no
     * longer generates or owns a separate certificate, so this default now matches the one
     * remoted_module's HTTPS server (/enroll's mTLS mode) presents. Read_Authd() is only ever
     * called from manager binaries (wazuh-manager-authd, wazuh-manager-remoted) -- there is no
     * agent-side caller this default would need to serve differently. */
    snprintf(manager_cert, OS_SIZE_1024 - 1, "etc/certs/remoted.pem");
    snprintf(manager_key, OS_SIZE_1024 - 1, "etc/certs/remoted-key.pem");

    // config->flags.disabled = AD_CONF_UNPARSED;
    /* If authd is defined, enable it by default */
    if (config->flags.disabled == AD_CONF_UNPARSED) {
        config->flags.disabled = AD_CONF_UNDEFINED;
    }
    config->port = 1515;
    config->flags.use_source_ip = 0;
    config->flags.clear_removed = 0;
    /* Off when <use_password> is omitted (upgrades); the installer template ships it on. */
    config->flags.use_password = 0;
    config->ciphers = strdup(DEFAULT_CIPHERS);
    config->flags.verify_host = 0;
    config->manager_cert = strdup(manager_cert);
    config->manager_key = strdup(manager_key);
    config->flags.remote_enrollment = 1;
    config->flags.legacy_enrollment = 1;
    config->force_options.enabled = true;
    config->force_options.key_mismatch = true;
    config->force_options.disconnected_time_enabled = true;
    config->force_options.disconnected_time = 3600;
    config->force_options.after_registration_time = 3600;

    if (!node)
        return 0;

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return OS_INVALID;
        } else if (!strcmp(node[i]->element, xml_disabled)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.disabled = b;
        } else if (!strcmp(node[i]->element, xml_port)) {
            config->port = (unsigned short)atoi(node[i]->content);

            if (!config->port) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, xml_ipv6)) {
            if (strcasecmp(node[i]->content, "yes") == 0) {
                config->ipv6 = true;
            } else if (strcasecmp(node[i]->content, "no") == 0) {
                config->ipv6 = false;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, xml_use_source_ip)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.use_source_ip = b;
        } else if (!strcmp(node[i]->element, xml_force)) {
            xml_node **chld_node = NULL;

            if (chld_node = OS_GetElementsbyNode(xml, node[i]), !chld_node) {
                merror(XML_INVELEM, node[i]->element);
                return  OS_INVALID;
            }

            if (w_read_force_config(chld_node, config)) {
                OS_ClearNode(chld_node);
                return OS_INVALID;
            }
            OS_ClearNode(chld_node);
        } else if (!strcmp(node[i]->element, xml_purge)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.clear_removed = b;
        } else if (!strcmp(node[i]->element, xml_use_password)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.use_password = b;
        } else if (!strcmp(node[i]->element, xml_remote_enrollment)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.remote_enrollment = b;
        } else if (!strcmp(node[i]->element, xml_legacy_enrollment)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.legacy_enrollment = b;
        } else if (!strcmp(node[i]->element, xml_ciphers)) {
            if (w_authd_validate_ciphers(node[i]->content) == OS_INVALID) {
                return OS_INVALID;
            }

            free(config->ciphers);
            config->ciphers = strdup(node[i]->content);
        } else if (!strcmp(node[i]->element, xml_ssl_agent_ca)) {
            free(config->agent_ca);
            config->agent_ca = strdup(node[i]->content);
        } else if (!strcmp(node[i]->element, xml_ssl_verify_host)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.verify_host = b;
        } else if (!strcmp(node[i]->element, xml_ssl_manager_cert)) {
            free(config->manager_cert);
            config->manager_cert = strdup(node[i]->content);
        } else if (!strcmp(node[i]->element, xml_ssl_manager_key)) {
            free(config->manager_key);
            config->manager_key = strdup(node[i]->content);
        } else if (strcasecmp(node[i]->element, xml_agents) == 0) {
            xml_node **children = OS_GetElementsbyNode(xml, node[i]);
            if (children == NULL) {
                continue;
            }

            w_authd_parse_agents(children, config);

            OS_ClearNode(children);

        } else {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        }
    }

    return 0;
}

short eval_bool(const char *str) {
    if (!str) {
        return OS_INVALID;
    } else if (!strcmp(str, "yes")) {
        return 1;
    } else if (!strcmp(str, "no")) {
        return 0;
    } else {
        return OS_INVALID;
    }
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

int w_read_force_config(XML_NODE node, authd_config_t *config) {
    /* XML Definitions */
    static const char *xml_enabled = "enabled";
    static const char *xml_key_mismatch = "key_mismatch";
    static const char *xml_disconnected_time = "disconnected_time";
    static const char *xml_after_registration_time = "after_registration_time";

    for (int i = 0; node[i]; i++) {
        // enabled
        if (!strcmp(node[i]->element, xml_enabled)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->force_options.enabled = b;
        }
        // key_mismatch
        else if (!strcmp(node[i]->element, xml_key_mismatch)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->force_options.key_mismatch = b;
        }
        // disconnected_time
        else if (!strcmp(node[i]->element, xml_disconnected_time)) {
            if (node[i]->attributes && node[i]->attributes[0]) {
                if (!strcmp(node[i]->attributes[0], xml_enabled)) {
                    if (node[i]->values && node[i]->values[0]) {

                        short b = eval_bool(node[i]->values[0]);

                        if (b < 0) {
                            merror(INV_VAL, node[i]->attributes[0]);
                            return OS_INVALID;
                        } else if (b > 0) {
                            config->force_options.disconnected_time_enabled = true;
                            if (get_time_interval(node[i]->content, &config->force_options.disconnected_time)) {
                                merror("Invalid interval for '%s' option", node[i]->element);
                                return OS_INVALID;
                            }
                        } else {
                            config->force_options.disconnected_time_enabled = false;
                        }
                    } else {
                        merror(INV_VAL, node[i]->attributes[0]);
                        return OS_INVALID;
                    }
                } else {
                    merror(XML_INVATTR, node[i]->attributes[0], node[i]->element);
                    return OS_INVALID;
                }
            } else {
                merror("Empty attribute for %s", node[i]->element);
                return OS_INVALID;
            }
        // after_registration_time
        } else if (!strcmp(node[i]->element, xml_after_registration_time)) {
            if (get_time_interval(node[i]->content, &config->force_options.after_registration_time)) {
                merror("Invalid interval for '%s' option", node[i]->element);
                return OS_INVALID;
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return OS_INVALID;
        }
    }
    return OS_SUCCESS;
}

STATIC void w_authd_parse_agents(XML_NODE node, authd_config_t * config) {
    const char * ALLOW_HIGHER_VERSIONS = "allow_higher_versions";

    int i = 0;
    while (node[i]) {
        if (strcasecmp(node[i]->element, ALLOW_HIGHER_VERSIONS) == 0) {
            if (strcmp(node[i]->content, "no") == 0) {
                config->allow_higher_versions = false;
            }
            else if (strcmp(node[i]->content, "yes") == 0) {
                config->allow_higher_versions = true;
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

#ifndef CLIENT
#include "mconf-config.h"

/* Same defaults Read_Authd() applies before iterating the XML nodes. */
static void w_authd_json_defaults(authd_config_t *config) {
    if (config->flags.disabled == AD_CONF_UNPARSED) {
        config->flags.disabled = AD_CONF_UNDEFINED;
    }
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

/* Reader of the `auth` section of the effective YAML document (mconf-config.h): same struct and
 * defaults as Read_Authd(); shared by wazuh-manager-authd and by remoted's enrollment bridge. */
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
