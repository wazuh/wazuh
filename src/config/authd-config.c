/*
 * Authd settings manager
 * Copyright (C) 2015-2019, Wazuh Inc.
 * May 29, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "authd-config.h"
#include "config.h"

static short eval_bool(const char *str);

int Read_Authd(XML_NODE node, void *d1, __attribute__((unused)) void *d2) {
    /* XML Definitions */
    static const char *xml_disabled = "disabled";
    static const char *xml_port = "port";
    static const char *xml_use_source_ip = "use_source_ip";
    static const char *xml_force_insert = "force_insert";
    static const char *xml_force_time = "force_time";
    static const char *xml_purge = "purge";
    static const char *xml_use_password = "use_password";
    static const char *xml_limit_maxagents = "limit_maxagents";
    static const char *xml_ciphers = "ciphers";
    static const char *xml_ssl_agent_ca = "ssl_agent_ca";
    static const char *xml_ssl_verify_host = "ssl_verify_host";
    static const char *xml_ssl_manager_cert = "ssl_manager_cert";
    static const char *xml_ssl_manager_key = "ssl_manager_key";
    static const char *xml_ssl_auto_negotiate = "ssl_auto_negotiate";

    authd_config_t *config = (authd_config_t *)d1;
    int i;

    char manager_cert[OS_SIZE_1024];
    char manager_key[OS_SIZE_1024];

    snprintf(manager_cert, OS_SIZE_1024 - 1, "%s/etc/sslmanager.cert", DEFAULTDIR);
    snprintf(manager_key, OS_SIZE_1024 - 1, "%s/etc/sslmanager.key", DEFAULTDIR);

    // config->flags.disabled = AD_CONF_UNPARSED;
    /* If authd is defined, enable it by default */
    if (config->flags.disabled == AD_CONF_UNPARSED) {
        config->flags.disabled = AD_CONF_UNDEFINED;
    }
    config->port = 1515;
    config->flags.use_source_ip = 0;
    config->flags.force_insert = 0;
    config->flags.clear_removed = 0;
    config->flags.use_password = 0;
    config->flags.register_limit = 1;
    config->ciphers = strdup("HIGH:!ADH:!EXP:!MD5:!RC4:!3DES:!CAMELLIA:@STRENGTH");
    config->flags.verify_host = 0;
    config->manager_cert = strdup(manager_cert);
    config->manager_key = strdup(manager_key);
    config->flags.auto_negotiate = 0;

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
        } else if (!strcmp(node[i]->element, xml_use_source_ip)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.use_source_ip = b;
        } else if (!strcmp(node[i]->element, xml_force_insert)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.force_insert = b;
        } else if (!strcmp(node[i]->element, xml_force_time)) {
            char *end;
            config->force_time = strtol(node[i]->content, &end, 10);

            if (*end != '\0') {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
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
        } else if (!strcmp(node[i]->element, xml_limit_maxagents)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.register_limit = b;
        } else if (!strcmp(node[i]->element, xml_ciphers)) {
            free(config->ciphers);
            config->ciphers = strdup(node[i]->content);
        }else if (!strcmp(node[i]->element, xml_ssl_agent_ca)) {
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
