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
#include "os_net/os_net.h"
#include "config.h"
#include "headers/sec.h"

int Read_Client_Server(XML_NODE node, agent *logr);
int Read_Client_Enrollment(XML_NODE node, agent *logr);

int Read_Client(const OS_XML *xml, XML_NODE node, void *d1, __attribute__((unused)) void *d2)
{
    int i = 0;
    char f_ip[128] = {'\0'};
    char * rip = NULL;
    int port = DEFAULT_SECURE;
    int protocol = IPPROTO_TCP;

    /* XML definitions */
    const char *xml_client_server = "server";
    const char *xml_local_ip = "local_ip";
    const char *xml_ar_disabled = "disable-active-response";
    const char *xml_notify_time = "notify_time";
    const char *xml_max_time_reconnect_try = "time-reconnect";
    const char *xml_force_reconnect_interval = "force_reconnect_interval";
    const char *xml_main_ip_update_interval = "ip_update_interval";
    const char *xml_profile_name = "config-profile";
    const char *xml_auto_restart = "auto_restart";
    const char *xml_crypto_method = "crypto_method";
    const char *xml_client_enrollment = "enrollment";

    /* Old XML definitions */
    const char *xml_client_ip = "server-ip";
    const char *xml_client_hostname = "server-hostname";
    const char *xml_client_port = "port";
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
        /* Get server IP */
        else if (strcmp(node[i]->element, xml_client_ip) == 0) {
            mwarn("The <%s> tag is deprecated, please use <server><address> instead.", xml_client_ip);

            if (OS_IsValidIP(node[i]->content, NULL) != 1) {
                merror(INVALID_IP, node[i]->content);
                return (OS_INVALID);
            }

            rip = node[i]->content;
        } else if (strcmp(node[i]->element, xml_client_hostname) == 0) {
            mwarn("The <%s> tag is deprecated, please use <server><address> instead.", xml_client_hostname);
            if (strchr(node[i]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s/", node[i]->content);
                rip = f_ip;
            } else {
                merror(AG_INV_HOST, node[i]->content);
                return (OS_INVALID);
            }

        } else if (strcmp(node[i]->element, xml_client_port) == 0) {
            mwarn("The <%s> tag is deprecated, please use <server><port> instead.", xml_client_port);

            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            if (port = atoi(node[i]->content), port <= 0 || port > 65535) {
                merror(PORT_ERROR, port);
                return (OS_INVALID);
            }
        }
        /* Get parameters for each configurated server*/
        else if (strcmp(node[i]->element, xml_client_server) == 0) {
            if (!(chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                merror(XML_INVELEM, node[i]->element);
                return (OS_INVALID);
            }
            if (Read_Client_Server(chld_node, logr) < 0) {
                OS_ClearNode(chld_node);
                return (OS_INVALID);
            }
            OS_ClearNode(chld_node);
        } else if (strcmp(node[i]->element, xml_client_enrollment) == 0) {
            if ((chld_node = OS_GetElementsbyNode(xml, node[i]))) {
                if (Read_Client_Enrollment(chld_node, logr) < 0) {
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
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
            logr->max_time_reconnect_try = atoi(node[i]->content);
            if (logr->max_time_reconnect_try < 0) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_force_reconnect_interval) == 0) {
            long t = w_parse_time(node[i]->content);
            if (t < 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                logr->force_reconnect_interval = t;
            }
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
            mwarn("The <%s> tag is deprecated, please use <server><protocol> instead.", xml_protocol);

            if (strcmp(node[i]->content, "tcp") == 0) {
                protocol = IPPROTO_TCP;
            } else if (strcmp(node[i]->content, "udp") == 0) {
                protocol = IPPROTO_UDP;
            } else {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if(strcmp(node[i]->element, xml_crypto_method) == 0){
            if(strcmp(node[i]->content, "blowfish") == 0){
                logr->crypto_method = W_METH_BLOWFISH;
            }
            else if(strcmp(node[i]->content, "aes") == 0){
                logr->crypto_method = W_METH_AES;
            }else{
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }

        // Add extra server (legacy configuration)
        if (rip) {
            os_realloc(logr->server, sizeof(agent_server) * (logr->server_count + 2), logr->server);
            os_strdup(rip, logr->server[logr->server_count].rip);
            logr->server[logr->server_count].port = 0;
            logr->server[logr->server_count].protocol = 0;
            // Since these are new options we will only leave a default for legacy configurations
            logr->server[logr->server_count].max_retries = DEFAULT_MAX_RETRIES;
            logr->server[logr->server_count].retry_interval = DEFAULT_RETRY_INTERVAL;
            memset(logr->server + logr->server_count + 1, 0, sizeof(agent_server));
            logr->server_count++;
        }
    }

    // Assign global port and protocol to legacy configurations

    for (i = 0; i < logr->server_count; ++i) {
        if (!logr->server[i].port) {
            logr->server[i].port = port;
        }

        if (!logr->server[i].protocol) {
            logr->server[i].protocol = protocol;
        }
    }
    return (0);
}

int Read_Client_Shared(XML_NODE node, void *d1)
{
    int i = 0;

    /* XML definitions */
    const char *xml_force_reconnect_interval = "force_reconnect_interval";

    agent * logr = (agent *)d1;
    logr->force_reconnect_interval = 0;

    for (i = 0; node[i]; i++) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        } else if (strcmp(node[i]->element, xml_force_reconnect_interval) == 0) {
            long t = w_parse_time(node[i]->content);
            if (t < 0) {
                mwarn(XML_VALUEERR, node[i]->element, node[i]->content);
            } else {
                logr->force_reconnect_interval = t;
            }
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
    }

    return (0);
}

int Read_Client_Server(XML_NODE node, agent * logr)
{
    /* XML definitions */
    const char *xml_client_addr = "address";
    const char *xml_client_port = "port";
    const char *xml_interface = "interface_index";
    const char *xml_protocol = "protocol";
    const char *xml_max_retries = "max_retries";
    const char *xml_retry_interval = "retry_interval";

    int j;
    char f_ip[128];
    char * rip = NULL;
    /* Default values */
    uint32_t network_interface = 0;
    int port = DEFAULT_SECURE;
    int protocol = IPPROTO_TCP;
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
        else if (strcmp(node[j]->element, xml_client_addr) == 0) {
            if (OS_IsValidIP(node[j]->content, NULL) == 1) {
                rip = node[j]->content;
            } else if (strchr(node[j]->content, '/') ==  NULL) {
                snprintf(f_ip, 127, "%s", node[j]->content);
                rip = f_ip;
            } else {
                merror(AG_INV_HOST, node[j]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_client_port) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }

            if (port = atoi(node[j]->content), port <= 0 || port > 65535) {
                merror(PORT_ERROR, port);
                return (OS_INVALID);
            }
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
            if (strcmp(node[j]->content, "tcp") == 0) {
                protocol = IPPROTO_TCP;
            } else if (strcmp(node[j]->content, "udp") == 0) {
                protocol = IPPROTO_UDP;
            } else {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_max_retries) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
            max_retries = atoi(node[j]->content);
            if (max_retries <= 0) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[j]->element, xml_retry_interval) == 0) {
            if (!OS_StrIsNum(node[j]->content)) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
            retry_interval = atoi(node[j]->content);
            if (retry_interval <= 0) {
                merror(XML_VALUEERR, node[j]->element, node[j]->content);
                return (OS_INVALID);
            }
        } else {
            merror(XML_INVELEM, node[j]->element);
            return (OS_INVALID);
        }
    }

    if (!rip) {
        merror("No such address in the configuration.");
        return (OS_INVALID);
    }

    os_realloc(logr->server, sizeof(agent_server) * (logr->server_count + 2), logr->server);
    os_strdup(rip, logr->server[logr->server_count].rip);
    if (strchr(logr->server[logr->server_count].rip, ':') != NULL) {
        os_realloc(logr->server[logr->server_count].rip, IPSIZE + 1, logr->server[logr->server_count].rip);
        OS_ExpandIPv6(logr->server[logr->server_count].rip, IPSIZE);
    }
    logr->server[logr->server_count].network_interface = network_interface;
    logr->server[logr->server_count].port = port;
    logr->server[logr->server_count].protocol = protocol;
    logr->server[logr->server_count].max_retries = max_retries;
    logr->server[logr->server_count].retry_interval = retry_interval;
    memset(logr->server + logr->server_count + 1, 0, sizeof(agent_server));
    logr->server_count++;

    return (0);
}

int Read_Client_Enrollment(XML_NODE node, agent * logr){
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
    const char *xml_auto_method = "auto_method";
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
        } else if (strcmp(node[j]->element, xml_auto_method) == 0) {
            if (!strcmp(node[j]->content, "yes")) {
                cert_cfg->auto_method = 1;
            } else if (!strcmp(node[j]->content, "no")) {
                cert_cfg->auto_method = 0;
            } else {
                merror("Invalid content for tag '%s'.", node[j]->element);
                w_enrollment_target_destroy(target_cfg);
                w_enrollment_cert_destroy(cert_cfg);
                return OS_INVALID;
            }
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

int Test_Client(const char * path){
    int fail = 0;
    agent test_client = { .server = NULL };

    if (ReadConfig(CAGENT_CONFIG | CCLIENT, path, &test_client, NULL) < 0) {
		merror(RCONFIG_ERROR,"Client", path);
		fail = 1;
	}

    Free_Client(&test_client);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}

void Free_Client(agent * config){
    if (config) {
        int i;

        if (config->server) {
            for (i = 0; config->server[i].rip; i++) {
                free(config->server[i].rip);
            }

            free(config->server);
        }

        free(config->profile);
        labels_free(config->labels);
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

/* Checks if at least one <server> block is not a link-local ipv6 address or it has a network interface configured. */
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
