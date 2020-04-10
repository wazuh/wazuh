/*
 * Wazuh Microsoft Office 365 module configuration
 * Copyright (C) 2015-2020, Wazuh Inc.
 * March 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_ENABLED = "enabled";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_TIMEOUT = "timeout";
static const char *XML_SKIP_ON_ERROR = "skip_on_error";
static const char *XML_INTERVAL = "interval";
static const char *XML_TENANT_ID = "tenant_id";
static const char *XML_CLIENT_ID = "client_id";
static const char *XML_CLIENT_SECRET = "client_secret";
static const char *XML_CLIENT_SECRET_PATH = "client_secret_path";
static const char *XML_SUBSCRIPTIONS = "subscriptions";
static const char *XML_SUBSCRIPTION = "subscription";
static const char *AAD_SUBSCRIPTION_TYPE = "Audit.AzureActiveDirectory";
static const char *DLP_SUBSCRIPTION_TYPE = "DLP.All";
static const char *EXCHANGE_SUBSCRIPTION_TYPE = "Audit.Exchange";
static const char *GENERAL_SUBSCRIPTION_TYPE = "Audit.General";
static const char *SHAREPOINT_SUBSCRIPTION_TYPE = "Audit.SharePoint";

static short eval_bool(const char *str) {
    return !str ? OS_INVALID : !strcmp(str, "yes") ? 1 : !strcmp(str, "no") ? 0 : OS_INVALID;
}

// Parse XML configuration
int wm_office365_read(const OS_XML *xml, xml_node **nodes, wmodule *module) {
    unsigned int i;
    unsigned int j;
    xml_node **children = NULL;
    wm_office365_t *office365_config;
    wm_office365_subscription_t *current_subscription = NULL;

    // Build default values
    if (!module->data) {
        os_calloc(1, sizeof(wm_office365_t), office365_config);
        office365_config->enabled = 1;
        office365_config->run_on_start = 1;
        office365_config->timeout = 30;
        office365_config->skip_on_error = 1;
        office365_config->tenant_id = NULL;
        office365_config->client_id = NULL;
        office365_config->client_secret = NULL;
        office365_config->client_secret_path = NULL;
        office365_config->subscriptions = NULL;
        module->context = &WM_OFFICE365_CONTEXT;
        module->tag = strdup(module->context->name);
        module->data = office365_config;
    }

    office365_config = module->data;

    if (!nodes) {
        return 0;
    }

    for (i = 0; nodes[i]; i++) {
        if (!nodes[i]->element) {
            mterror(WM_OFFICE365_LOGTAG, XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_ENABLED)) {
            int enabled = eval_bool(nodes[i]->content);

            if (enabled == OS_INVALID) {
                mterror(WM_OFFICE365_LOGTAG, "Invalid content for tag '%s'.", XML_ENABLED);
                return OS_INVALID;
            }

            office365_config->enabled = enabled;
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            int run_on_start = eval_bool(nodes[i]->content);

            if (run_on_start == OS_INVALID) {
                mterror(WM_OFFICE365_LOGTAG, "Invalid content for tag '%s'.", XML_RUN_ON_START);
                return OS_INVALID;
            }

            office365_config->run_on_start = run_on_start;
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            char *endptr;
            office365_config->timeout = strtol(nodes[i]->content, &endptr, 0);

            if (*endptr || office365_config->timeout < 0) {
                mterror(WM_OFFICE365_LOGTAG, "Invalid content for tag '%s'.", XML_TIMEOUT);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_SKIP_ON_ERROR)) {
            int skip_on_error = eval_bool(nodes[i]->content);

            if (skip_on_error == OS_INVALID) {
                mterror(WM_OFFICE365_LOGTAG, "Invalid content for tag '%s'.", XML_SKIP_ON_ERROR);
                return OS_INVALID;
            }

            office365_config->skip_on_error = skip_on_error;
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            if (strlen(nodes[i]->content) == 0) {
                mterror(WM_OFFICE365_LOGTAG, "Empty content for tag '%s'.", XML_INTERVAL);
                return OS_INVALID;
            }

            char *endptr;
            office365_config->interval = strtoul(nodes[i]->content, &endptr, 0);

            if ((office365_config->interval == 0 && endptr == nodes[i]->content) || office365_config->interval == ULONG_MAX) {
                mterror(WM_OFFICE365_LOGTAG, "Invalid content for tag '%s'.", XML_INTERVAL);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                office365_config->interval *= 86400;
                break;
            case 'h':
                office365_config->interval *= 3600;
                break;
            case 'm':
                office365_config->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                mterror(WM_OFFICE365_LOGTAG, "Invalid content for tag '%s'.", XML_INTERVAL);
                return OS_INVALID;
            }

            if (office365_config->interval > 86400) {
                mterror(WM_OFFICE365_LOGTAG, "Max. interval is 1 day.");
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_TENANT_ID)) {
            if (strlen(nodes[i]->content) != 0) {
                free(office365_config->tenant_id);
                os_strdup(nodes[i]->content, office365_config->tenant_id);
            } else {
                mterror(WM_OFFICE365_LOGTAG, "Empty content for tag '%s'.", XML_TENANT_ID);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_CLIENT_ID)) {
            if (strlen(nodes[i]->content) != 0) {
                free(office365_config->client_id);
                os_strdup(nodes[i]->content, office365_config->client_id);
            } else {
                mterror(WM_OFFICE365_LOGTAG, "Empty content for tag '%s'.", XML_CLIENT_ID);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_CLIENT_SECRET)) {
            if (strlen(nodes[i]->content) != 0) {
                free(office365_config->client_secret);
                os_strdup(nodes[i]->content, office365_config->client_secret);
            }
        } else if (!strcmp(nodes[i]->element, XML_CLIENT_SECRET_PATH)) {
            if (strlen(nodes[i]->content) != 0) {
                free(office365_config->client_secret_path);
                os_strdup(nodes[i]->content, office365_config->client_secret_path);
            }
        } else if (!strcmp(nodes[i]->element, XML_SUBSCRIPTIONS)) {
            // Expand subscription child nodes
            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }

            mtdebug2(WM_OFFICE365_LOGTAG, "Loop through child nodes.");

            for (j = 0; children[j]; j++) {

                mtdebug2(WM_OFFICE365_LOGTAG, "Parsing child node: %s.", children[j]->element);

                if (!children[j]->element) {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                // Create subscription node
                if (current_subscription) {
                    os_calloc(1, sizeof(wm_office365_subscription_t), current_subscription->next);
                    current_subscription = current_subscription->next;
                    mtdebug2(WM_OFFICE365_LOGTAG, "Creating new subscription structure.");
                } else {
                    // First subscription
                    os_calloc(1, sizeof(wm_office365_subscription_t), current_subscription);
                    office365_config->subscriptions = current_subscription;
                    mtdebug2(WM_OFFICE365_LOGTAG, "Creating first subscription structure.");
                }

                // Start
                if (!strcmp(children[j]->element, XML_SUBSCRIPTION)) {
                    if (strlen(children[j]->content) != 0) {
                        if (!strcmp(children[j]->content, AAD_SUBSCRIPTION_TYPE)
                            || !strcmp(children[j]->content, DLP_SUBSCRIPTION_TYPE)
                            || !strcmp(children[j]->content, EXCHANGE_SUBSCRIPTION_TYPE)
                            || !strcmp(children[j]->content, GENERAL_SUBSCRIPTION_TYPE)
                            || !strcmp(children[j]->content, SHAREPOINT_SUBSCRIPTION_TYPE)) {
                            os_strdup(children[j]->content, current_subscription->name);
                        } else {
                            mterror(WM_OFFICE365_LOGTAG, "Invalid subscription '%s'. Valid ones are '%s', '%s', '%s', '%s', or '%s'.", 
                                children[j]->content, AAD_SUBSCRIPTION_TYPE, DLP_SUBSCRIPTION_TYPE, EXCHANGE_SUBSCRIPTION_TYPE,
                                GENERAL_SUBSCRIPTION_TYPE, SHAREPOINT_SUBSCRIPTION_TYPE); 
                            return OS_INVALID;
                        }
                    } else {
                        mterror(WM_OFFICE365_LOGTAG, "Empty subscription. Valid ones are '%s', '%s', '%s', '%s', or '%s'.", 
                            AAD_SUBSCRIPTION_TYPE, DLP_SUBSCRIPTION_TYPE, EXCHANGE_SUBSCRIPTION_TYPE, GENERAL_SUBSCRIPTION_TYPE,
                            SHAREPOINT_SUBSCRIPTION_TYPE);
                        return OS_INVALID;
                    }
                }
            }
        }
    }

    if (!office365_config->client_secret && !office365_config->client_secret_path) {
        mterror(WM_OFFICE365_LOGTAG, "No client secret or client secret path settings found.");
        return OS_INVALID;
    }

    if (!office365_config->subscriptions) {
        mtwarn(WM_OFFICE365_LOGTAG, "No subscriptions found.");
        return OS_INVALID;
    }

    return 0;
}
