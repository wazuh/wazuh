/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#if defined(WIN32) || defined(__linux__) || defined(__MACH__)

#include "wazuh_modules/wmodules.h"

static const char *XML_ENABLED                  = "enabled";
static const char *XML_ONLY_FUTURE_EVENTS       = "only_future_events";
static const char *XML_INTERVAL                 = "interval";
static const char *XML_CURL_MAX_SIZE            = "curl_max_size";

static const char *XML_API_AUTH             = "api_auth";
static const char *XML_TENANT_ID            = "tenant_id";
static const char *XML_CLIENT_ID            = "client_id";
static const char *XML_CLIENT_SECRET_PATH   = "client_secret_path";
static const char *XML_CLIENT_SECRET        = "client_secret";
static const char *XML_API_TYPE             = "api_type";

static const char *XML_SUBSCRIPTIONS                = "subscriptions";
static const char *XML_SUBSCRIPTION                 = "subscription";

// Parse XML
int wm_office365_read(__attribute__((unused)) const OS_XML *xml, xml_node **nodes, wmodule *module) {

    int i = 0;
    int j = 0;
    xml_node **children = NULL;
    wm_office365* office365_config = NULL;
    wm_office365_auth *office365_auth = NULL;
    wm_office365_subscription *office365_subscription = NULL;

    if (!module->data) {
        // Default initialization
        module->context = &WM_OFFICE365_CONTEXT;
        module->tag = strdup(module->context->name);
        os_calloc(1, sizeof(wm_office365), office365_config);

        office365_config->enabled =            WM_OFFICE365_DEFAULT_ENABLED;
        office365_config->only_future_events = WM_OFFICE365_DEFAULT_ONLY_FUTURE_EVENTS;
        office365_config->interval =           WM_OFFICE365_DEFAULT_INTERVAL;
        office365_config->curl_max_size =      WM_OFFICE365_DEFAULT_CURL_MAX_SIZE;

        module->data = office365_config;
    } else {
        office365_config = module->data;
    }

    if (!nodes) {
        return OS_INVALID;
    }

    for (i = 0; nodes[i]; i++) {
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                office365_config->enabled = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                office365_config->enabled = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ENABLED, WM_OFFICE365_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_ONLY_FUTURE_EVENTS)) {
            if (!strcmp(nodes[i]->content, "yes"))
                office365_config->only_future_events = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                office365_config->only_future_events = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_ONLY_FUTURE_EVENTS, WM_OFFICE365_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            office365_config->interval = w_parse_time(nodes[i]->content);
            if ((office365_config->interval < 0) || (office365_config->interval > W_DAY_SECONDS)) {
                merror("Invalid content for tag '%s' at module '%s'. The maximum value allowed is 1 day.", XML_INTERVAL, WM_OFFICE365_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_CURL_MAX_SIZE)) {
            office365_config->curl_max_size = w_parse_size(nodes[i]->content);
            if (office365_config->curl_max_size < 1024) {
                merror("Invalid content for tag '%s' at module '%s'. The minimum value allowed is 1KB.", XML_CURL_MAX_SIZE, WM_OFFICE365_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_API_AUTH)) {
            // Create auth node
            if (office365_auth) {
                os_calloc(1, sizeof(wm_office365_auth), office365_auth->next);
                office365_auth = office365_auth->next;
            } else {
                // First office365_auth
                os_calloc(1, sizeof(wm_office365_auth), office365_auth);
                office365_config->auth = office365_auth;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, XML_TENANT_ID)) {
                    if (strlen(children[j]->content) == 0) {
                        merror("Empty content for tag '%s' at module '%s'.", XML_TENANT_ID, WM_OFFICE365_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                    os_free(office365_auth->tenant_id);
                    os_strdup(children[j]->content, office365_auth->tenant_id);
                } else if (!strcmp(children[j]->element, XML_CLIENT_ID)) {
                    if (strlen(children[j]->content) == 0) {
                        merror("Empty content for tag '%s' at module '%s'.", XML_CLIENT_ID, WM_OFFICE365_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                    os_free(office365_auth->client_id);
                    os_strdup(children[j]->content, office365_auth->client_id);
                } else if (!strcmp(children[j]->element, XML_CLIENT_SECRET_PATH)) {
                    if (strlen(children[j]->content) == 0) {
                        merror("Empty content for tag '%s' at module '%s'.", XML_CLIENT_SECRET_PATH, WM_OFFICE365_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                    os_free(office365_auth->client_secret_path);
                    os_strdup(children[j]->content, office365_auth->client_secret_path);
                } else if (!strcmp(children[j]->element, XML_CLIENT_SECRET)) {
                    if (strlen(children[j]->content) == 0) {
                        merror("Empty content for tag '%s' at module '%s'.", XML_CLIENT_SECRET, WM_OFFICE365_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                    os_free(office365_auth->client_secret);
                    os_strdup(children[j]->content, office365_auth->client_secret);
                } else if (!strcmp(children[j]->element, XML_API_TYPE)) {
                    if (strlen(children[j]->content) == 0) {
                        merror("Empty content for tag '%s' at module '%s'.", XML_API_TYPE, WM_OFFICE365_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                    else if (!strcmp(children[j]->content, "commercial")) {
                        os_free(office365_auth->login_fqdn);
                        os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, office365_auth->login_fqdn);
                        os_free(office365_auth->management_fqdn);
                        os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, office365_auth->management_fqdn);
                    }
                    else if (!strcmp(children[j]->content, "gcc")) {
                        os_free(office365_auth->login_fqdn);
                        os_strdup(WM_OFFICE365_GCC_API_LOGIN_FQDN, office365_auth->login_fqdn);
                        os_free(office365_auth->management_fqdn);
                        os_strdup(WM_OFFICE365_GCC_API_MANAGEMENT_FQDN, office365_auth->management_fqdn);
                    }
                    else if (!strcmp(children[j]->content, "gcc-high")) {
                        os_free(office365_auth->login_fqdn);
                        os_strdup(WM_OFFICE365_GCC_HIGH_API_LOGIN_FQDN, office365_auth->login_fqdn);
                        os_free(office365_auth->management_fqdn);
                        os_strdup(WM_OFFICE365_GCC_HIGH_API_MANAGEMENT_FQDN, office365_auth->management_fqdn);
                    }
                    else {
                        merror("Invalid content for tag '%s' at module '%s'.", XML_API_TYPE, WM_OFFICE365_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else {
                    merror("No such tag '%s' at module '%s'.", children[j]->element, WM_OFFICE365_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);

            if (office365_auth->client_secret_path) {
                if (office365_auth->client_secret) {
                    merror("It is not allowed to set 'client_secret' and 'client_secret_path' at module '%s'.", WM_OFFICE365_CONTEXT.name);
                    return OS_INVALID;
                }
                if(waccess(office365_auth->client_secret_path, F_OK) != 0 ) {
                    merror("Invalid content for tag '%s' at module '%s': The path cannot be opened.", XML_CLIENT_SECRET_PATH, WM_OFFICE365_CONTEXT.name);
                    return OS_INVALID;
                }
            } else if (!office365_auth->client_secret) {
                merror("'%s' is missing at module '%s'.", XML_CLIENT_SECRET, WM_OFFICE365_CONTEXT.name);
                return OS_INVALID;
            }

            if (!office365_auth->client_id) {
                merror("'%s' is missing at module '%s'.", XML_CLIENT_ID, WM_OFFICE365_CONTEXT.name);;
                return OS_INVALID;
            } else if (!office365_auth->tenant_id) {
                merror("'%s' is missing at module '%s'.", XML_TENANT_ID, WM_OFFICE365_CONTEXT.name);
                return OS_INVALID;
            }

            // Keep retrocompatibility with configs made prior to GCC (High) support
            if (!office365_auth->login_fqdn && !office365_auth->management_fqdn) {
                os_free(office365_auth->login_fqdn);
                os_strdup(WM_OFFICE365_DEFAULT_API_LOGIN_FQDN, office365_auth->login_fqdn);
                os_free(office365_auth->management_fqdn);
                os_strdup(WM_OFFICE365_DEFAULT_API_MANAGEMENT_FQDN, office365_auth->management_fqdn);
            }

        } else if (!strcmp(nodes[i]->element, XML_SUBSCRIPTIONS)) {
            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }
            for (j = 0; children[j]; j++) {

                if (!strcmp(children[j]->element, XML_SUBSCRIPTION)) {
                    if (strlen(children[j]->content) == 0) {
                        merror("Empty content for tag '%s' at module '%s'.", XML_SUBSCRIPTION, WM_OFFICE365_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                    if (office365_subscription) {
                        os_calloc(1, sizeof(wm_office365_subscription), office365_subscription->next);
                        office365_subscription = office365_subscription->next;
                    } else {
                        os_calloc(1, sizeof(wm_office365_subscription), office365_subscription);
                        office365_config->subscription = office365_subscription;
                    }
                    os_strdup(children[j]->content, office365_subscription->subscription_name);
                } else {
                    merror("No such tag '%s' at module '%s'.", children[j]->element, WM_OFFICE365_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }
            OS_ClearNode(children);
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_OFFICE365_CONTEXT.name);
            return OS_INVALID;
        }
    }

    /* Validation process */
    if (!office365_auth) {
        merror("Empty content for tag '%s' at module '%s'.", XML_API_AUTH, WM_OFFICE365_CONTEXT.name);
        return OS_INVALID;
    }
    if (!office365_subscription) {
        merror("Empty content for tag '%s' at module '%s'.", XML_SUBSCRIPTIONS, WM_OFFICE365_CONTEXT.name);
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

#endif
