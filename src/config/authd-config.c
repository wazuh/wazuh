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
#include "os_xml/os_xml.h"
#include "shared.h"
#include "authd-config.h"
#include "config.h"
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
    static const char *xml_force_insert = "force_insert";       // Deprecated since 4.3.0
    static const char *xml_force_time = "force_time";           // Deprecated since 4.3.0
    static const char *xml_force = "force";
    static const char *xml_purge = "purge";
    static const char *xml_use_password = "use_password";
    static const char *xml_limit_maxagents = "limit_maxagents";
    static const char *xml_ciphers = "ciphers";
    static const char *xml_ssl_agent_ca = "ssl_agent_ca";
    static const char *xml_ssl_verify_host = "ssl_verify_host";
    static const char *xml_ssl_manager_cert = "ssl_manager_cert";
    static const char *xml_ssl_manager_key = "ssl_manager_key";
    static const char *xml_ssl_auto_negotiate = "ssl_auto_negotiate";
    static const char *xml_remote_enrollment = "remote_enrollment";
    static const char *xml_agents = "agents";
#ifndef CLIENT
    static const char *xml_key_request = "key_request";
#endif

    authd_config_t *config = (authd_config_t *)d1;
    int i;

    char manager_cert[OS_SIZE_1024];
    char manager_key[OS_SIZE_1024];

    snprintf(manager_cert, OS_SIZE_1024 - 1, "etc/sslmanager.cert");
    snprintf(manager_key, OS_SIZE_1024 - 1, "etc/sslmanager.key");

    // config->flags.disabled = AD_CONF_UNPARSED;
    /* If authd is defined, enable it by default */
    if (config->flags.disabled == AD_CONF_UNPARSED) {
        config->flags.disabled = AD_CONF_UNDEFINED;
    }
    config->port = 1515;
    config->flags.use_source_ip = 0;
    config->flags.clear_removed = 0;
    config->flags.use_password = 0;
    config->ciphers = strdup("HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH");
    config->flags.verify_host = 0;
    config->manager_cert = strdup(manager_cert);
    config->manager_key = strdup(manager_key);
    config->flags.auto_negotiate = 0;
    config->flags.remote_enrollment = 1;
    config->force_options.enabled = true;
    config->force_options.key_mismatch = true;
    config->force_options.disconnected_time_enabled = true;
    config->force_options.disconnected_time = 3600;
    config->force_options.after_registration_time = 3600;

    short legacy_force_insert = -1;
    int legacy_force_time = -1;
    bool new_force_read = false;

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
        } else if (!strcmp(node[i]->element, xml_force_insert)) {
            mwarn("The <%s> tag is deprecated. Use <%s> instead.", xml_force_insert, xml_force);
            short b = eval_bool(node[i]->content);
            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
            legacy_force_insert = b;
        } else if (!strcmp(node[i]->element, xml_force_time)) {
            mwarn("The <%s> tag is deprecated. Use <%s> instead.", xml_force_time, xml_force);
            char *end;
            int b = strtol(node[i]->content, &end, 10);
            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
            legacy_force_time = b;
        } else if (!strcmp(node[i]->element, xml_force)) {
            new_force_read = true;

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
#ifndef CLIENT
        } else if (!strcmp(node[i]->element, xml_key_request)) {
            XML_NODE children = OS_GetElementsbyNode(xml, node[i]);

            if (children == NULL) {
                continue;
            }

            authd_read_key_request(children, config);
            config->key_request.compatibility_flag = 1;
            OS_ClearNode(children);
#endif
        } else if (!strcmp(node[i]->element, xml_limit_maxagents)) {
            mdebug1("The <%s> tag is deprecated since version 4.1.0.", xml_limit_maxagents);
        } else if (!strcmp(node[i]->element, xml_ciphers)) {
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
        } else if (!strcmp(node[i]->element, xml_ssl_auto_negotiate)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.auto_negotiate = b;
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

    if (!new_force_read) {
        if (legacy_force_insert != -1) {
            config->force_options.enabled = legacy_force_insert;

            mdebug1("Setting <force><enabled> tag to %s to comply with the legacy <%s> option found.",
                    legacy_force_insert ? "'yes'" : "'no'", xml_force_insert);
        }
        if (legacy_force_time != -1) {
            if (legacy_force_time == 0) {
                config->force_options.disconnected_time_enabled = false;
            }
            config->force_options.disconnected_time = legacy_force_time;

            mdebug1("Setting <force><disconnected_time> tag to '%d' to comply with the legacy <%s> option found.",
                legacy_force_time, xml_force_time);
        }
        mdebug1("The tag <force><after_registration_time> is not defined. Applied default value: '%ld'",
                config->force_options.after_registration_time);
        mdebug1("The tag <force><key_mismatch> is not defined. Applied default value: '%s'",
                config->force_options.key_mismatch ? "true" : "false");
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

#endif
