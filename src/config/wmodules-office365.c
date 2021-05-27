/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
*/

#if defined (WIN32) || (__linux__) || defined (__MACH__)

#include "wazuh_modules/wmodules.h"

static const char *XML_ENABLED                  = "enabled";
static const char *XML_ONLY_FUTURE_EVENTS       = "only_future_events";
static const char *XML_INTERVAL                 = "interval";

static const char *XML_API_AUTH             = "api_auth";
static const char *XML_TENANT_ID            = "tenant_id";
static const char *XML_CLIENT_ID            = "client_id";
static const char *XML_CLIENT_SECRET_PATH   = "client_secret_path";
static const char *XML_CLIENT_SECRET        = "client_secret";

static const char *XML_SUBSCRIPTIONS                = "subscriptions";
static const char *XML_SUBSCRIPTION                 = "subscription";
static const char *SUBSCRIPTIONS_TYPE_AZURE_AD      = "Audit.AzureActiveDirectory";
static const char *SUBSCRIPTIONS_TYPE_EXCHANGE      = "Audit.Exchange";
static const char *SUBSCRIPTIONS_TYPE_SHAREPOINT    = "Audit.SharePoint";
static const char *SUBSCRIPTIONS_TYPE_GENERAL       = "Audit.General";
static const char *SUBSCRIPTIONS_TYPE_ALL           = "DLP.All";

time_t time_convert_1d(const char *time_c) {
    char *endptr;
    time_t time_i = strtoul(time_c, &endptr, 0);

    if (time_i <= 0 || time_i >= UINT_MAX) {
        return OS_INVALID;
    }

    switch (*endptr) {
    case 'd':
        if(time_i > 1) {
            return OS_INVALID;
        }
        time_i *= 86400;
        break;
    case 'h':
        if(time_i > 24) {
            return OS_INVALID;
        }
        time_i *= 3600;
        break;
    case 'm':
        if(time_i > 1440) {
            return OS_INVALID;
        }
        time_i *= 60;
        break;
    case 's':
        if(time_i > 86400) {
            return OS_INVALID;
        }
        break;
    case '\0':
        break;
    default:
        return OS_INVALID;
    }
    return time_i;
}

// Parse XML
int wm_office365_read(__attribute__((unused)) const OS_XML *xml, xml_node **nodes, wmodule *module) {

    int i = 0;
    int j = 0;
    xml_node **children = NULL;
    wm_office365* office365_config = NULL;
    wm_office365_auth *office365_auth = NULL;

    if (!module->data) {
        // Default initialization
        module->context = &WM_OFFICE365_CONTEXT;
        module->tag = strdup(module->context->name);
        os_calloc(1, sizeof(wm_office365), office365_config);

        office365_config->enabled =            WM_OFFICE365_DEFAULT_ENABLED;
        office365_config->only_future_events = WM_OFFICE365_DEFAULT_ONLY_FUTURE_EVENTS;
        office365_config->interval =           WM_OFFICE365_DEFAULT_INTERVAL;

        office365_config->subscription.azure        = WM_OFFICE365_DEFAULT_AZURE;
        office365_config->subscription.exchange     = WM_OFFICE365_DEFAULT_EXCHANGE;
        office365_config->subscription.sharepoint   = WM_OFFICE365_DEFAULT_SHAREPOINT;
        office365_config->subscription.general      = WM_OFFICE365_DEFAULT_GENERAL;
        office365_config->subscription.dlp          = WM_OFFICE365_DEFAULT_DLP;

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
            office365_config->interval = time_convert_1d(nodes[i]->content);
            if (office365_config->interval == OS_INVALID) {
                merror("Invalid content for tag '%s' at module '%s'. The maximum value allowed is 1 day.", XML_INTERVAL, WM_OFFICE365_CONTEXT.name);
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
                if(access(office365_auth->client_secret_path, F_OK) != 0 ) {
                    merror("At module '%s': The path cannot be opened.", WM_OFFICE365_CONTEXT.name);
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

        } else if (!strcmp(nodes[i]->element, XML_SUBSCRIPTIONS)) {
            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }
            for (j = 0; children[j]; j++) {
                if (!strcmp(children[j]->element, XML_SUBSCRIPTION)) {
                    if (!strcmp(children[j]->content, SUBSCRIPTIONS_TYPE_AZURE_AD)) {
                        office365_config->subscription.azure = 1;
                    } else if (!strcmp(children[j]->content, SUBSCRIPTIONS_TYPE_EXCHANGE)) {
                        office365_config->subscription.exchange = 1;
                    } else if (!strcmp(children[j]->content, SUBSCRIPTIONS_TYPE_SHAREPOINT)) {
                        office365_config->subscription.sharepoint = 1;
                    } else if (!strcmp(children[j]->content, SUBSCRIPTIONS_TYPE_GENERAL)) {
                        office365_config->subscription.general = 1;
                    } else if (!strcmp(children[j]->content, SUBSCRIPTIONS_TYPE_ALL)) {
                        office365_config->subscription.dlp = 1;
                    } else {
                        merror("Invalid content for tag '%s' at module '%s'.", children[j]->element, WM_OFFICE365_CONTEXT.name);
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
    if (!office365_config->subscription.azure &&
        !office365_config->subscription.exchange &&
        !office365_config->subscription.general &&
        !office365_config->subscription.sharepoint &&
        !office365_config->subscription.dlp)
    {
        mwarn("At module '%s': No subscription was provided, everything will be monitored by default.", WM_OFFICE365_CONTEXT.name);
        office365_config->subscription.azure = 1;
        office365_config->subscription.exchange = 1;
        office365_config->subscription.sharepoint = 1;
        office365_config->subscription.general = 1;
        office365_config->subscription.dlp = 1;
    }

    return OS_SUCCESS;
}

#endif
