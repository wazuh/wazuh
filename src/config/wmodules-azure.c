/*
 * Wazuh Module Configuration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * December, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef CLIENT
#ifndef WIN32
#include "wazuh_modules/wmodules.h"

static const char *XML_TIMEOUT = "timeout";
static const char *XML_INTERVAL = "interval";
static const char *XML_RUN_DAY = "day";
static const char *XML_RUN_WDAY = "wday";
static const char *XML_RUN_TIME = "time";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_DISABLED = "disabled";

static const char *XML_LOG_ANALYTICS = "log_analytics";
static const char *XML_GRAPH = "graph";
static const char *XML_STORAGE = "storage";

static const char *XML_APP_ID = "application_id";
static const char *XML_APP_KEY = "application_key";
static const char *XML_AUTH_PATH = "auth_path";
static const char *XML_TENANTDOMAIN = "tenantdomain";
static const char *XML_REQUEST = "request";

static const char *XML_ACCOUNT_NAME = "account_name";
static const char *XML_ACCOUNT_KEY = "account_key";
static const char *XML_TAG = "tag";
static const char *XML_CONTAINER = "container";
static const char *XML_CONTAINER_NAME = "name";
static const char *XML_CONTAINER_BLOBS = "blobs";
static const char *XML_CONTAINER_TYPE="content_type";

static const char *XML_REQUEST_QUERY = "query";
static const char *XML_TIME_OFFSET = "time_offset";
static const char *XML_WORKSPACE = "workspace";

static int wm_azure_api_read(const OS_XML *xml, XML_NODE nodes, wm_azure_api_t * api_config, char **output);
static int wm_azure_request_read(XML_NODE nodes, wm_azure_request_t * request, unsigned int type, char **output);
static int wm_azure_storage_read(const OS_XML *xml, XML_NODE nodes, wm_azure_storage_t * storage, char **output);
static int wm_azure_container_read(XML_NODE nodes, wm_azure_container_t * container, char **output);

static void wm_clean_api(wm_azure_api_t * api_config);
static void wm_clean_request(wm_azure_request_t * request);
static void wm_clean_storage(wm_azure_storage_t * storage);
static void wm_clean_container(wm_azure_container_t * container);

// Parse XML

int wm_azure_read(const OS_XML *xml, xml_node **nodes, wmodule *module, char **output)
{
    int i = 0;
    wm_azure_t *azure;
    wm_azure_api_t *api_config = NULL;
    wm_azure_api_t *api_config_prev = NULL;
    wm_azure_storage_t *storage = NULL;
    wm_azure_storage_t *storage_prev = NULL;
    int month_interval = 0;
    char message[OS_FLSIZE];

    // Create module

    os_calloc(1, sizeof(wm_azure_t), azure);
    azure->flags.enabled = 1;
    azure->flags.run_on_start = 1;
    azure->scan_wday = -1;
    azure->scan_time = NULL;
    azure->timeout = WM_AZURE_DEF_TIMEOUT;
    module->context = &WM_AZURE_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = azure;

    if (!nodes) {
        if (output == NULL) {
            mwarn("Empty configuration at module '%s'.", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE, "Empty configuration at module '%s'.", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        XML_NODE children = NULL;

        if (!nodes[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            azure->timeout = atol(nodes[i]->content);

            if (azure->timeout <= 0 || azure->timeout >= UINT_MAX) {
                if (output == NULL) {
                    merror("At module '%s': Invalid timeout.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE, "At module '%s': Invalid timeout.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            azure->interval = strtoul(nodes[i]->content, &endptr, 0);

            if (azure->interval <= 0 || azure->interval >= UINT_MAX) {
                if (output == NULL) {
                    merror("At module '%s': Invalid interval.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE, "At module '%s': Invalid interval.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'M':
                month_interval = 1;
                azure->interval *= 60; // We can`t calculate seconds of a month
                break;
            case 'w':
                azure->interval *= 604800;
                break;
            case 'd':
                azure->interval *= 86400;
                break;
            case 'h':
                azure->interval *= 3600;
                break;
            case 'm':
                azure->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                if (output == NULL) {
                    merror("At module '%s': Invalid interval.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE, "At module '%s': Invalid interval.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            if (azure->interval < 60) {
                if (output == NULL) {
                    merror("At module '%s': Interval must be greater than 60 seconds. New interval value: 60s.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Interval must be greater than 60 seconds. New interval value: 60s.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                azure->interval = 60;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_DAY)) {
            if (!OS_StrIsNum(nodes[i]->content)) {
                if (output == NULL) {
                    merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.", nodes[i]->element, nodes[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            } else {
                azure->scan_day = atoi(nodes[i]->content);
                if (azure->scan_day < 1 || azure->scan_day > 31) {
                    if (output == NULL) {
                        merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                    } else {
                        snprintf(message, OS_FLSIZE,
                            "Invalid value for element '%s': %s.", nodes[i]->element, nodes[i]->content);
                        wm_strcat(output, message, '\n');
                    }
                    return OS_INVALID;
                }
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_WDAY)) {
            azure->scan_wday = w_validate_wday(nodes[i]->content);
            if (azure->scan_wday < 0 || azure->scan_wday > 6) {
                if (output == NULL) {
                    merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.", nodes[i]->element, nodes[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_TIME)) {
            azure->scan_time = w_validate_time(nodes[i]->content);
            if (!azure->scan_time) {
                if (output == NULL) {
                    merror(XML_VALUEERR, nodes[i]->element, nodes[i]->content);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.", nodes[i]->element, nodes[i]->content);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                azure->flags.run_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                azure->flags.run_on_start = 0;
            else {
                if (output == NULL) {
                    merror("At module '%s': Invalid content for tag '%s'.", WM_AZURE_CONTEXT.name, XML_RUN_ON_START);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid content for tag '%s'.", WM_AZURE_CONTEXT.name, XML_RUN_ON_START);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                azure->flags.enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                azure->flags.enabled = 1;
            else {
                if (output == NULL) {
                    merror("At module '%s': Invalid content for tag '%s'.", WM_AZURE_CONTEXT.name, XML_DISABLED);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid content for tag '%s'.", WM_AZURE_CONTEXT.name, XML_DISABLED);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_LOG_ANALYTICS)) {

            if (api_config) {
                os_calloc(1, sizeof(wm_azure_api_t), api_config->next);
                api_config_prev = api_config;
                api_config = api_config->next;
            } else {
                // First API configuration block
                os_calloc(1, sizeof(wm_azure_api_t), api_config);
                azure->api_config = api_config;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                if (output == NULL) {
                    merror(XML_INVELEM, nodes[i]->element);
                } else {
                    snprintf(message, OS_FLSIZE, "Invalid element in the configuration: '%s'.", nodes[i]->element);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            api_config->type = LOG_ANALYTICS;
            if (wm_azure_api_read(xml, children, api_config, output) < 0) {
                wm_clean_api(api_config);
                if (api_config_prev) {
                    api_config = api_config_prev;
                    api_config->next = NULL;
                } else {
                    azure->api_config = api_config = NULL;
                }
            }

            OS_ClearNode(children);

        } else if (!strcmp(nodes[i]->element, XML_GRAPH)) {

            if (api_config) {
                os_calloc(1, sizeof(wm_azure_api_t), api_config->next);
                api_config_prev = api_config;
                api_config = api_config->next;
            } else {
                // First API configuration block
                os_calloc(1, sizeof(wm_azure_api_t), api_config);
                azure->api_config = api_config;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                if (output == NULL) {
                    merror(XML_INVELEM, nodes[i]->element);
                } else {
                    snprintf(message, OS_FLSIZE, "Invalid element in the configuration: '%s'.", nodes[i]->element);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            api_config->type = GRAPHS;
            if (wm_azure_api_read(xml, children, api_config, output) < 0) {
                wm_clean_api(api_config);
                if (api_config_prev) {
                    api_config = api_config_prev;
                    api_config->next = NULL;
                } else {
                    azure->api_config = api_config = NULL;
                }
            }

            OS_ClearNode(children);

        } else if (!strcmp(nodes[i]->element, XML_STORAGE)) {

            if (storage) {
                os_calloc(1, sizeof(wm_azure_storage_t), storage->next);
                storage_prev = storage;
                storage = storage->next;
            } else {
                // First API configuration block
                os_calloc(1, sizeof(wm_azure_storage_t), storage);
                azure->storage = storage;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                if (output == NULL) {
                    merror(XML_INVELEM, nodes[i]->element);
                } else {
                    snprintf(message, OS_FLSIZE, "Invalid element in the configuration: '%s'.", nodes[i]->element);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            if (wm_azure_storage_read(xml, children, storage, output) < 0) {
                wm_clean_storage(storage);
                if (storage_prev) {
                    storage = storage_prev;
                    storage->next = NULL;
                } else {
                    azure->storage = storage = NULL;
                }
            }

            OS_ClearNode(children);

        } else {
            if (output == NULL) {
                merror("At module '%s': No such tag '%s'.", WM_AZURE_CONTEXT.name, nodes[i]->element);
            } else {
                snprintf(message, OS_FLSIZE, "At module '%s': No such tag '%s'.",
                    WM_AZURE_CONTEXT.name, nodes[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;
        }
    }

    // Validate scheduled scan parameters and interval value

    if (azure->scan_day && (azure->scan_wday >= 0)) {
        if (output == NULL) {
            merror("At module '%s': 'day' is not compatible with 'wday'.", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': 'day' is not compatible with 'wday'.", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    } else if (azure->scan_day) {
        if (!month_interval) {
            if (output == NULL) {
                mwarn("At module '%s': Interval must be a multiple of one month. New interval value: 1M.", WM_AZURE_CONTEXT.name);
            } else {
                snprintf(message, OS_FLSIZE,
                    "WARNING: At module '%s': Interval must be a multiple of one month. New interval value: 1M.",
                    WM_AZURE_CONTEXT.name);
                wm_strcat(output, message, '\n');
            }
            azure->interval = 60; // 1 month
        }
        if (!azure->scan_time)
            azure->scan_time = strdup("00:00");
    } else if (azure->scan_wday >= 0) {
        if (w_validate_interval(azure->interval, 1) != 0) {
            azure->interval = 604800;  // 1 week
            if (output == NULL) {
                mwarn("At module '%s': Interval must be a multiple of one week. New interval value: 1w.", WM_AZURE_CONTEXT.name);
            } else {
                snprintf(message, OS_FLSIZE,
                    "WARNING: At module '%s': Interval must be a multiple of one week. New interval value: 1w.",
                    WM_AZURE_CONTEXT.name);
                wm_strcat(output, message, '\n');
            }
        }
        if (azure->interval == 0)
            azure->interval = 604800;
        if (!azure->scan_time)
            azure->scan_time = strdup("00:00");
    } else if (azure->scan_time) {
        if (w_validate_interval(azure->interval, 0) != 0) {
            azure->interval = WM_DEF_INTERVAL;  // 1 day
            if (output == NULL) {
                mwarn("At module '%s': Interval must be a multiple of one day. New interval value: 1d.", WM_AZURE_CONTEXT.name);
            } else {
                snprintf(message, OS_FLSIZE,
                    "WARNING: At module '%s': Interval must be a multiple of one day. New interval value: 1d.",
                    WM_AZURE_CONTEXT.name);
                wm_strcat(output, message, '\n');
            }
        }
    }
    if (!azure->interval)
        azure->interval = WM_DEF_INTERVAL;

    return 0;
}

int wm_azure_api_read(const OS_XML *xml, XML_NODE nodes, wm_azure_api_t * api_config, char **output) {

    int i = 0;
    wm_azure_request_t *request = NULL;
    wm_azure_request_t *request_prev = NULL;
    char message[OS_FLSIZE];

    api_config->application_id = NULL;
    api_config->application_key = NULL;
    api_config->auth_path = NULL;
    api_config->tenantdomain = NULL;

    for (i = 0; nodes[i]; i++) {
        XML_NODE children = NULL;

        if (!nodes[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return OS_INVALID;

        } else if (!nodes[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, nodes[i]->element);
            } else {
                snprintf(message, OS_FLSIZE, "Invalid NULL content for element: %s.", nodes[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;

        } else if (!strcmp(nodes[i]->element, XML_APP_ID)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, api_config->application_id);
        } else if (!strcmp(nodes[i]->element, XML_APP_KEY)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, api_config->application_key);
        } else if (!strcmp(nodes[i]->element, XML_AUTH_PATH)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, api_config->auth_path);
        } else if (!strcmp(nodes[i]->element, XML_TENANTDOMAIN)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, api_config->tenantdomain);
        } else if (!strcmp(nodes[i]->element, XML_REQUEST)) {

            if (request) {
                os_calloc(1, sizeof(wm_azure_request_t), request->next);
                request_prev = request;
                request = request->next;
            } else {
                // First request block
                os_calloc(1, sizeof(wm_azure_request_t), request);
                api_config->request = request;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                if (output == NULL) {
                    merror(XML_INVELEM, nodes[i]->element);
                } else {
                    snprintf(message, OS_FLSIZE, "Invalid element in the configuration: '%s'.", nodes[i]->element);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            if (wm_azure_request_read(children, request, api_config->type, output) < 0) {
                wm_clean_request(request);
                if (request_prev) {
                    request = request_prev;
                    request->next = NULL;
                } else {
                    api_config->request = request = NULL;
                }
            }

            OS_ClearNode(children);

        } else {
            if (output == NULL) {
                merror(XML_INVELEM, nodes[i]->element);
            } else {
                snprintf(message, OS_FLSIZE, "Invalid element in the configuration: '%s'.", nodes[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;
        }
    }

    /* Validation process */
    if (!api_config->auth_path) {
        if (!api_config->application_id || !api_config->application_key) {
            if (output == NULL) {
                merror("At module '%s': No authentication method provided. Skipping block...", WM_AZURE_CONTEXT.name);
            } else {
                snprintf(message, OS_FLSIZE,
                    "At module '%s': No authentication method provided. Skipping block...", WM_AZURE_CONTEXT.name);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;
        }
    }

    if (!api_config->tenantdomain) {
        if (output == NULL) {
            merror("At module '%s': No tenant domain defined. Skipping block...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No tenant domain defined. Skipping block...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    if (!api_config->request) {
        if (output == NULL) {
            merror("At module '%s': No request defined. Skipping block...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No request defined. Skipping block...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    return 0;
}

int wm_azure_request_read(XML_NODE nodes, wm_azure_request_t * request, unsigned int type, char **output) {

    int i = 0;
    char message[OS_FLSIZE];

    request->tag = NULL;
    request->query = NULL;
    request->time_offset = NULL;
    request->workspace = NULL;

    for (i = 0; nodes[i]; i++) {

        if (!nodes[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return OS_INVALID;

        } else if (!nodes[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, nodes[i]->element);
            } else {
                snprintf(message, OS_FLSIZE, "Invalid NULL content for element: %s.", nodes[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;

        } else if (!strcmp(nodes[i]->element, XML_TAG)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, request->tag);
        } else if (!strcmp(nodes[i]->element, XML_REQUEST_QUERY)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, request->query);
        } else if (!strcmp(nodes[i]->element, XML_TIME_OFFSET)) {
            char *endptr;
            unsigned int offset = strtoul(nodes[i]->content, &endptr, 0);

            if (offset <= 0 || offset >= UINT_MAX) {
                if (output == NULL) {
                    merror("At module '%s': Invalid time offset.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE, "At module '%s': Invalid time offset.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            if (*endptr != 'm' && *endptr != 'h' && *endptr != 'd') {
                if (output == NULL) {
                    merror("At module '%s': Invalid time offset: It should be specified minutes, hours or days.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid time offset: It should be specified minutes, hours or days.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content, request->time_offset);

        } else if (!strcmp(nodes[i]->element, XML_WORKSPACE)) {
            if (type == LOG_ANALYTICS) {
                if (*nodes[i]->content != '\0')
                    os_strdup(nodes[i]->content, request->workspace);
            } else {
                if (output == NULL) {
                    minfo("At module '%s': Workspace ID only available for Log Analytics API. Skipping it...", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "INFO: At module '%s': Workspace ID only available for Log Analytics API. Skipping it...", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
            }
        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            request->timeout = atol(nodes[i]->content);

            if (request->timeout <= 0 || request->timeout >= UINT_MAX) {
                if (output == NULL) {
                    merror("At module '%s': Invalid timeout.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE, "At module '%s': Invalid timeout.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else {
            if (output == NULL) {
                merror(XML_INVELEM, nodes[i]->element);
            } else {
                snprintf(message, OS_FLSIZE, "Invalid element in the configuration: '%s'.", nodes[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;
        }
    }

    /* Validation process */
    if (!request->tag) {
        if (output == NULL) {
            minfo("At module '%s': No request tag defined. Setting it randomly...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "INFO: At module '%s': No request tag defined. Setting it randomly...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        int random_id = os_random();
        char * rtag;

        os_calloc(OS_SIZE_128, sizeof(char), rtag);

        if (random_id < 0)
            random_id = -random_id;

        snprintf(rtag, OS_SIZE_128, "request_%d", random_id);
        os_strdup(rtag, request->tag);
        free(rtag);
    }

    if (!request->query) {
        if (output == NULL) {
            merror("At module '%s': No query defined. Skipping request block...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No query defined. Skipping request block...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    if (!request->time_offset) {
        if (output == NULL) {
            merror("At module '%s': No time offset defined. Skipping request block...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No time offset defined. Skipping request block...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    if (!request->workspace && type == LOG_ANALYTICS) {
        if (output == NULL) {
            merror("At module '%s': No Workspace ID defined. Skipping request block...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No Workspace ID defined. Skipping request block...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    return 0;
}

int wm_azure_storage_read(const OS_XML *xml, XML_NODE nodes, wm_azure_storage_t * storage, char **output) {

    int i = 0;
    wm_azure_container_t *container = NULL;
    wm_azure_container_t *container_prev = NULL;
    char message[OS_FLSIZE];

    storage->account_name = NULL;
    storage->account_key = NULL;
    storage->auth_path = NULL;
    storage->tag = NULL;

    for (i = 0; nodes[i]; i++) {
        XML_NODE children = NULL;

        if (!nodes[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return OS_INVALID;

        } else if (!nodes[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, nodes[i]->element);
            } else {
                snprintf(message, OS_FLSIZE, "Invalid NULL content for element: %s.", nodes[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;

        } else if (!strcmp(nodes[i]->element, XML_ACCOUNT_NAME)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, storage->account_name);
        } else if (!strcmp(nodes[i]->element, XML_ACCOUNT_KEY)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, storage->account_key);
        } else if (!strcmp(nodes[i]->element, XML_AUTH_PATH)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, storage->auth_path);
        } else if (!strcmp(nodes[i]->element, XML_TAG)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, storage->tag);
        } else if (!strcmp(nodes[i]->element, XML_CONTAINER)) {

            if (container) {
                os_calloc(1, sizeof(wm_azure_container_t), container->next);
                container_prev = container;
                container = container->next;
            } else {
                // First request block
                os_calloc(1, sizeof(wm_azure_container_t), container);
                storage->container = container;
            }

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                if (output == NULL) {
                    merror(XML_INVELEM, nodes[i]->element);
                } else {
                    snprintf(message, OS_FLSIZE, "Invalid element in the configuration: '%s'.", nodes[i]->element);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            // Read name attribute
            if (nodes[i]->attributes) {
                if (!strcmp(nodes[i]->attributes[0], XML_CONTAINER_NAME) && *nodes[i]->values[0] != '\0') {
                    os_strdup(nodes[i]->values[0], container->name);
                } else {
                    if (output == NULL) {
                        minfo("At module '%s': Invalid container name. Skipping container...", WM_AZURE_CONTEXT.name);
                    } else {
                        snprintf(message, OS_FLSIZE,
                            "INFO: At module '%s': Invalid container name. Skipping container...", WM_AZURE_CONTEXT.name);
                        wm_strcat(output, message, '\n');
                    }
                    wm_clean_container(container);
                    if (container_prev) {
                        container = container_prev;
                        container->next = NULL;
                    } else {
                        storage->container = container = NULL;
                    }
                    OS_ClearNode(children);
                    continue;
                }
            } else {
                if (output == NULL) {
                    minfo("At module '%s': Container name not found. Skipping container...", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "INFO: At module '%s': Container name not found. Skipping container...", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                wm_clean_container(container);
                if (container_prev) {
                    container = container_prev;
                    container->next = NULL;
                } else {
                    storage->container = container = NULL;
                }
                OS_ClearNode(children);
                continue;
            }

            if (wm_azure_container_read(children, container, output) < 0) {
                wm_clean_container(container);
                if (container_prev) {
                    container = container_prev;
                    container->next = NULL;
                } else {
                    storage->container = container = NULL;
                }
            }

            OS_ClearNode(children);

        } else {
            if (output == NULL) {
                merror(XML_INVELEM, nodes[i]->element);
            } else {
                snprintf(message, OS_FLSIZE, "Invalid element in the configuration: '%s'.", nodes[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;
        }
    }

    /* Validation process */
    if (!storage->auth_path) {
        if (!storage->account_name || !storage->account_key) {
            if (output == NULL) {
                merror("At module '%s': No authentication method provided. Skipping block...", WM_AZURE_CONTEXT.name);
            } else {
                snprintf(message, OS_FLSIZE,
                    "At module '%s': No authentication method provided. Skipping block...", WM_AZURE_CONTEXT.name);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;
        }
    }

    if (!storage->tag) {
        if (output == NULL) {
            minfo("At module '%s': No storage tag defined. Setting it randomly...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No storage tag defined. Setting it randomly...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        int random_id = os_random();
        char * rtag;

        os_calloc(OS_SIZE_128, sizeof(char), rtag);

        if (random_id < 0)
            random_id = -random_id;

        snprintf(rtag, OS_SIZE_128, "storage_%d", random_id);
        os_strdup(rtag, storage->tag);
        free(rtag);
    }

    if (!storage->container) {
        if (output == NULL) {
            merror("At module '%s': No container defined. Skipping block...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No container defined. Skipping block...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    return 0;
}

int wm_azure_container_read(XML_NODE nodes, wm_azure_container_t * container, char **output) {

    int i = 0;
    char message[OS_FLSIZE];

    container->blobs = NULL;
    container->time_offset = NULL;
    container->content_type = NULL;

    for (i = 0; nodes[i]; i++) {

        if (!nodes[i]->element) {
            if (output == NULL) {
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return OS_INVALID;

        } else if (!nodes[i]->content) {
            if (output == NULL) {
                merror(XML_VALUENULL, nodes[i]->element);
            } else {
                snprintf(message, OS_FLSIZE, "Invalid NULL content for element: %s.", nodes[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;

        } else if (!strcmp(nodes[i]->element, XML_CONTAINER_BLOBS)) {
            if (*nodes[i]->content != '\0')
                os_strdup(nodes[i]->content, container->blobs);
        } else if (!strcmp(nodes[i]->element, XML_CONTAINER_TYPE)) {
            if (strncmp(nodes[i]->content, "json_file", 9) && strncmp(nodes[i]->content, "json_inline", 11) && strncmp(nodes[i]->content, "text", 4)) {
                if (output == NULL) {
                    merror("At module '%s': Invalid content type. It should be 'json_file', 'json_inline' or 'text'.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid content type. It should be 'json_file', 'json_inline' or 'text'.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
            os_strdup(nodes[i]->content, container->content_type);
        } else if (!strcmp(nodes[i]->element, XML_TIME_OFFSET)) {
            char *endptr;
            unsigned int offset = strtoul(nodes[i]->content, &endptr, 0);

            if (offset <= 0 || offset >= UINT_MAX) {
                if (output == NULL) {
                    merror("At module '%s': Invalid time offset.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE, "At module '%s': Invalid time offset.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            if (*endptr != 'm' && *endptr != 'h' && *endptr != 'd') {
                if (output == NULL) {
                    merror("At module '%s': Invalid time offset: It should be specified minutes, hours or days.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid time offset: It should be specified minutes, hours or days.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }

            os_strdup(nodes[i]->content, container->time_offset);

        } else if (!strcmp(nodes[i]->element, XML_TIMEOUT)) {
            container->timeout = atol(nodes[i]->content);

            if (container->timeout <= 0 || container->timeout >= UINT_MAX) {
                if (output == NULL) {
                    merror("At module '%s': Invalid timeout.", WM_AZURE_CONTEXT.name);
                } else {
                    snprintf(message, OS_FLSIZE,
                        "At module '%s': Invalid timeout.", WM_AZURE_CONTEXT.name);
                    wm_strcat(output, message, '\n');
                }
                return OS_INVALID;
            }
        } else {
            if (output == NULL) {
                merror(XML_INVELEM, nodes[i]->element);
            } else {
                snprintf(message, OS_FLSIZE, "Invalid element in the configuration: '%s'.", nodes[i]->element);
                wm_strcat(output, message, '\n');
            }
            return OS_INVALID;
        }
    }

    /* Validation process */
    if (!container->blobs) {
        if (output == NULL) {
            merror("At module '%s': No blobs defined. Skipping container block...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No blobs defined. Skipping container block...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    if (!container->time_offset) {
        if (output == NULL) {
            merror("At module '%s': No time offset defined. Skipping container block...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No time offset defined. Skipping container block...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    if (!container->content_type) {
        if (output == NULL) {
            merror("At module '%s': No content type defined. Skipping container block...", WM_AZURE_CONTEXT.name);
        } else {
            snprintf(message, OS_FLSIZE,
                "At module '%s': No content type defined. Skipping container block...", WM_AZURE_CONTEXT.name);
            wm_strcat(output, message, '\n');
        }
        return OS_INVALID;
    }

    return 0;
}


void wm_clean_api(wm_azure_api_t * api_config) {

    wm_azure_request_t *curr_request = NULL;
    wm_azure_request_t *next_request = NULL;

    if (api_config->application_id)
        free(api_config->application_id);
    if (api_config->application_key)
        free(api_config->application_key);
    if (api_config->auth_path)
        free(api_config->auth_path);
    if (api_config->tenantdomain)
        free(api_config->tenantdomain);

    for (curr_request = api_config->request; curr_request; curr_request = next_request) {

        next_request = curr_request->next;
        wm_clean_request(curr_request);
    }

    free(api_config);
}

void wm_clean_request(wm_azure_request_t * request) {

    if (request->tag)
        free(request->tag);
    if (request->query)
        free(request->query);
    if (request->workspace)
        free(request->workspace);
    if (request->time_offset)
        free(request->time_offset);

    free(request);
}


void wm_clean_storage(wm_azure_storage_t * storage) {

    wm_azure_container_t *curr_container = NULL;
    wm_azure_container_t *next_container = NULL;

    if (storage->account_name)
        free(storage->account_name);
    if (storage->account_key)
        free(storage->account_key);
    if (storage->auth_path)
        free(storage->auth_path);
    if (storage->tag)
        free(storage->tag);

    for (curr_container = storage->container; curr_container; curr_container = next_container) {

        next_container = curr_container->next;
        wm_clean_container(curr_container);
    }

    free(storage);
}

void wm_clean_container(wm_azure_container_t * container) {

    if (container->name)
        free(container->name);
    if (container->blobs)
        free(container->blobs);
    if (container->content_type)
        free(container->content_type);
    if (container->time_offset)
        free(container->time_offset);

    free(container);
}

#endif
#endif
