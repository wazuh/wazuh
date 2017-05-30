/*
 * Authd settings manager
 * Copyright (C) 2017 Wazuh Inc.
 * May 29, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

/*
<auth>
  <!-- Default configuration -->
  <port>1515</port>
  <use-source-ip>no</use-source-ip>
  <force-margin>-1</force-margin>
  <clear-removed>no</clear-removed>
  <use-password>no</use-password>
  <ssl-agent-ca>PATH</ssl-agent-ca>
  <ssl-verify-host>no</ssl-verify-host>
  <ssl-manager-cert>/var/ossec/etc/sslmanager.cert</ssl-manager-cert>
  <ssl-manager-key>/var/ossec/etc/sslmanager.key</ssl-manager-key>
  <ssl-auto-negotiate>no</ssl-auto-negotiate>
</auth>
*/

#include "shared.h"
#include "authd-config.h"
#include "config.h"

static short eval_bool(const char *str);

int Read_Authd(XML_NODE node, void *d1, __attribute__((unused)) void *d2) {
    /* XML Definitions */
    static const char *xml_port = "port";
    static const char *xml_use_source_ip = "use-source-ip";
    static const char *xml_force_margin = "force-margin";
    static const char *xml_clear_removed = "clear-removed";
    static const char *xml_use_password = "use-password";
    static const char *xml_ssl_agent_ca = "ssl-agent-ca";
    static const char *xml_ssl_verify_host = "ssl-verify-host";
    static const char *xml_ssl_manager_cert = "ssl-manager-cert";
    static const char *xml_ssl_manager_key = "ssl-manager-key";
    static const char *xml_ssl_auto_negotiate = "ssl-auto-negotiate";

    authd_config_t *config = (authd_config_t *)d1;
    int i;

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL, __local_name);
            return OS_INVALID;
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, __local_name, node[i]->element);
            return OS_INVALID;
        } else if (!strcmp(node[i]->element, xml_port)) {
            config->port = (unsigned short)atoi(node[i]->content);

            if (!config->port) {
                merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, xml_use_source_ip)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.use_source_ip = b;
        } else if (!strcmp(node[i]->element, xml_force_margin)) {
            char *end;
            config->force_time = strtol(node[i]->content, &end, 10);

            if (*end != '\0') {
                merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                return OS_INVALID;
            }
        } else if (!strcmp(node[i]->element, xml_clear_removed)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.clear_removed = b;
        } else if (!strcmp(node[i]->element, xml_use_password)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.use_password = b;
        } else if (!strcmp(node[i]->element, xml_ssl_agent_ca)) {
            free(config->agent_ca);
            config->agent_ca = strdup(node[i]->content);
        } else if (!strcmp(node[i]->element, xml_ssl_verify_host)) {
            short b = eval_bool(node[i]->content);

            if (b < 0) {
                merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
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
                merror(XML_VALUEERR, __local_name, node[i]->element, node[i]->content);
                return OS_INVALID;
            }

            config->flags.auto_negotiate = b;
        } else {
            merror(XML_INVELEM, __local_name, node[i]->element);
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
