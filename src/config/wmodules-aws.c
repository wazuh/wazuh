/*
 * Wazuh Module Configuration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * October 26, 2017.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_DISABLED = "disabled";
static const char *XML_BUCKET = "bucket";
static const char *XML_SERVICE = "service";
static const char *XML_INTERVAL = "interval";
static const char *XML_ACCESS_KEY = "access_key";
static const char *XML_SECRET_KEY = "secret_key";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_REMOVE_FORM_BUCKET = "remove_from_bucket";
static const char *XML_SKIP_ON_ERROR = "skip_on_error";
static const char *XML_AWS_PROFILE = "aws_profile";
static const char *XML_IAM_ROLE_ARN = "iam_role_arn";
static const char *XML_AWS_ACCOUNT_ID = "aws_account_id";
static const char *XML_AWS_ACCOUNT_ALIAS = "aws_account_alias";
static const char *XML_TRAIL_PREFIX = "path";
static const char *XML_ONLY_LOGS_AFTER = "only_logs_after";
static const char *XML_REGION = "regions";
static const char *XML_BUCKET_TYPE = "type";
static const char *XML_SERVICE_TYPE = "type";
static const char *XML_BUCKET_NAME = "name";

static const char *LEGACY_AWS_ACCOUNT_ALIAS = "LEGACY";

static const char *CLOUDTRAIL_BUCKET_TYPE = "cloudtrail";
static const char *CONFIG_BUCKET_TYPE = "config";
static const char *VPCFLOW_BUCKET_TYPE = "vpcflow";
static const char *CUSTOM_BUCKET_TYPE = "custom";
static const char *GUARDDUTY_BUCKET_TYPE = "guardduty";
static const char *INSPECTOR_SERVICE_TYPE = "inspector";

// Parse XML

int wm_aws_read(const OS_XML *xml, xml_node **nodes, wmodule *module)
{
    int i = 0;
    int j = 0;
    xml_node **children = NULL;
    wm_aws *aws_config;
    wm_aws_bucket *cur_bucket = NULL;
    wm_aws_service *cur_service = NULL;

    if (!nodes) {
        mwarn("Tag <%s> not found at module '%s'.", XML_BUCKET, WM_AWS_CONTEXT.name);
        return OS_INVALID;
    }

    // Create module

    os_calloc(1, sizeof(wm_aws), aws_config);
    aws_config->enabled = 1;
    aws_config->run_on_start = 1;
    aws_config->remove_from_bucket = 0;
    aws_config->interval = WM_AWS_DEFAULT_INTERVAL;
    module->context = &WM_AWS_CONTEXT;
    module->tag = strdup(module->context->name);
    module->data = aws_config;

    // Iterate over module subelements

    for (i = 0; nodes[i]; i++){
        if (!nodes[i]->element) {
            merror(XML_ELEMNULL);
            return OS_INVALID;
        } else if (!strcmp(nodes[i]->element, XML_DISABLED)) {
            if (!strcmp(nodes[i]->content, "yes"))
                aws_config->enabled = 0;
            else if (!strcmp(nodes[i]->content, "no"))
                aws_config->enabled = 1;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_DISABLED, WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_INTERVAL)) {
            char *endptr;
            aws_config->interval = strtoul(nodes[i]->content, &endptr, 0);

            if ((aws_config->interval == 0 && endptr == nodes[i]->content) || aws_config->interval == ULONG_MAX) {
                merror("Invalid interval at module '%s'", WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }

            switch (*endptr) {
            case 'd':
                aws_config->interval *= 86400;
                break;
            case 'h':
                aws_config->interval *= 3600;
                break;
            case 'm':
                aws_config->interval *= 60;
                break;
            case 's':
            case '\0':
                break;
            default:
                merror("Invalid interval at module '%s'", WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_RUN_ON_START)) {
            if (!strcmp(nodes[i]->content, "yes"))
                aws_config->run_on_start = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                aws_config->run_on_start = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_RUN_ON_START, WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_SKIP_ON_ERROR)) {
            if (!strcmp(nodes[i]->content, "yes"))
                aws_config->skip_on_error = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                aws_config->skip_on_error = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_SKIP_ON_ERROR, WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_REMOVE_FORM_BUCKET)) {
            if (!strcmp(nodes[i]->content, "yes"))
                aws_config->remove_from_bucket = 1;
            else if (!strcmp(nodes[i]->content, "no"))
                aws_config->remove_from_bucket = 0;
            else {
                merror("Invalid content for tag '%s' at module '%s'.", XML_REMOVE_FORM_BUCKET, WM_AWS_CONTEXT.name);
                return OS_INVALID;
            }
        } else if (!strcmp(nodes[i]->element, XML_ACCESS_KEY)) {
            if (strlen(nodes[i]->content) != 0) {
                free(aws_config->access_key);
                os_strdup(nodes[i]->content, aws_config->access_key);
            }
        } else if (!strcmp(nodes[i]->element, XML_SECRET_KEY)) {
            if (strlen(nodes[i]->content) != 0) {
                free(aws_config->secret_key);
                os_strdup(nodes[i]->content, aws_config->secret_key);
            }
        } else if (!strcmp(nodes[i]->element, XML_BUCKET)) {
            if (!nodes[i]->attributes) { // Legacy
                if (strlen(nodes[i]->content) == 0) {
                    merror("Empty content for tag '%s' at module '%s'.", XML_BUCKET, WM_AWS_CONTEXT.name);
                    return OS_INVALID;
                }

                free(aws_config->bucket);
                os_strdup(nodes[i]->content, aws_config->bucket);
            } else {
                mtdebug2(WM_AWS_LOGTAG, "Found a bucket tag");
                // Create bucket node
                if (cur_bucket) {
                    os_calloc(1, sizeof(wm_aws_bucket), cur_bucket->next);
                    cur_bucket = cur_bucket->next;
                    mtdebug2(WM_AWS_LOGTAG, "Creating another bucket structure");
                } else {
                    // First bucket
                    os_calloc(1, sizeof(wm_aws_bucket), cur_bucket);
                    aws_config->buckets = cur_bucket;
                    mtdebug2(WM_AWS_LOGTAG, "Creating first bucket structure");
                }

                // Expand bucket Child Nodes

                if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                    continue;
                }

                // type is an attribute of the bucket tag
                if (!strcmp(*nodes[i]->attributes, XML_BUCKET_TYPE)) {
                    if (!strcmp(*nodes[i]->values, CLOUDTRAIL_BUCKET_TYPE) || !strcmp(*nodes[i]->values, CONFIG_BUCKET_TYPE)
                        || !strcmp(*nodes[i]->values, CUSTOM_BUCKET_TYPE) || !strcmp(*nodes[i]->values, GUARDDUTY_BUCKET_TYPE)
                        || !strcmp(*nodes[i]->values, VPCFLOW_BUCKET_TYPE)) {
                        os_strdup(*nodes[i]->values, cur_bucket->type);
                    } else {
                        mterror(WM_AWS_LOGTAG, "Invalid bucket type '%s'. Valid ones are '%s', '%s', '%s', '%s' or '%s'", *nodes[i]->values, CLOUDTRAIL_BUCKET_TYPE,
                            CONFIG_BUCKET_TYPE, CUSTOM_BUCKET_TYPE, GUARDDUTY_BUCKET_TYPE, VPCFLOW_BUCKET_TYPE);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else {
                    mterror(WM_AWS_LOGTAG, "Attribute name '%s' is not valid. The valid one is '%s'.", *nodes[i]->attributes, XML_BUCKET_TYPE);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                mtdebug2(WM_AWS_LOGTAG, "Loop thru child nodes");
                for (j = 0; children[j]; j++) {

                    mtdebug2(WM_AWS_LOGTAG, "Parse child node: %s", children[j]->element);

                    if (!children[j]->element) {
                        merror(XML_ELEMNULL);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }

                    // Start
                    if (!strcmp(children[j]->element, XML_BUCKET_NAME)) {
                        if (strlen(children[j]->content) == 0) {
                            merror("Empty content for tag '%s' at module '%s'.", XML_BUCKET_NAME, WM_AWS_CONTEXT.name);
                            OS_ClearNode(children);
                            return OS_INVALID;
                        }
                        free(cur_bucket->bucket);
                        os_strdup(children[j]->content, cur_bucket->bucket);
                    } else if (!strcmp(children[j]->element, XML_AWS_ACCOUNT_ID)) {
                        if (strlen(children[j]->content) == 0) {
                            merror("Empty content for tag '%s' at module '%s'.", XML_BUCKET, WM_AWS_CONTEXT.name);
                            OS_ClearNode(children);
                            return OS_INVALID;
                        }
                        free(cur_bucket->aws_account_id);
                        os_strdup(children[j]->content, cur_bucket->aws_account_id);
                    } else if (!strcmp(children[j]->element, XML_REMOVE_FORM_BUCKET)) {
                        if (!strcmp(children[j]->content, "yes")) {
                            cur_bucket->remove_from_bucket = 1;
                        } else if (!strcmp(children[j]->content, "no")) {
                            cur_bucket->remove_from_bucket = 0;
                        } else {
                            merror("Invalid content for tag '%s' at module '%s'.", XML_REMOVE_FORM_BUCKET, WM_AWS_CONTEXT.name);
                            OS_ClearNode(children);
                            return OS_INVALID;
                        }
                    } else if (!strcmp(children[j]->element, XML_ACCESS_KEY)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->access_key);
                            os_strdup(children[j]->content, cur_bucket->access_key);
                        }
                    } else if (!strcmp(children[j]->element, XML_AWS_ACCOUNT_ALIAS)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->aws_account_alias);
                            os_strdup(children[j]->content, cur_bucket->aws_account_alias);
                        }
                    } else if (!strcmp(children[j]->element, XML_SECRET_KEY)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->secret_key);
                            os_strdup(children[j]->content, cur_bucket->secret_key);
                        }
                    } else if (!strcmp(children[j]->element, XML_AWS_PROFILE)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->aws_profile);
                            os_strdup(children[j]->content, cur_bucket->aws_profile);
                        }
                    } else if (!strcmp(children[j]->element, XML_IAM_ROLE_ARN)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->iam_role_arn);
                            os_strdup(children[j]->content, cur_bucket->iam_role_arn);
                        }
                    } else if (!strcmp(children[j]->element, XML_TRAIL_PREFIX)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->trail_prefix);
                            os_strdup(children[j]->content, cur_bucket->trail_prefix);
                        }
                    } else if (!strcmp(children[j]->element, XML_ONLY_LOGS_AFTER)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->only_logs_after);
                            os_strdup(children[j]->content, cur_bucket->only_logs_after);
                        }
                    } else if (!strcmp(children[j]->element, XML_REGION)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->regions);
                            os_strdup(children[j]->content, cur_bucket->regions);
                        }
                    } else {
                        merror("No such child tag '%s' of bucket at module '%s'.", children[j]->element, WM_AWS_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                }
                OS_ClearNode(children);
            }
        // for services
        } else if (!strcmp(nodes[i]->element, XML_SERVICE)) {

            mtdebug2(WM_AWS_LOGTAG, "Found a service tag");

            if (!nodes[i]->attributes) {
                mterror(WM_AWS_LOGTAG, "Undefined type for service.");
                return OS_INVALID;
            }
            // Create service node
            if (cur_service) {
                os_calloc(1, sizeof(wm_aws_service), cur_service->next);
                cur_service = cur_service->next;
                mtdebug2(WM_AWS_LOGTAG, "Creating another service structure");
            } else {
                // First service
                os_calloc(1, sizeof(wm_aws_service), cur_service);
                aws_config->services = cur_service;
                mtdebug2(WM_AWS_LOGTAG, "Creating first service structure");
            }

            // type is an attribute of the service tag
            if (!strcmp(*nodes[i]->attributes, XML_SERVICE_TYPE)) {
                if (!nodes[i]->values) {
                    mterror(WM_AWS_LOGTAG, "Empty service type. Valid one is '%s'", INSPECTOR_SERVICE_TYPE);
                    return OS_INVALID;
                } else if (!strcmp(*nodes[i]->values, INSPECTOR_SERVICE_TYPE)) {
                    os_strdup(*nodes[i]->values, cur_service->type);
                } else {
                    mterror(WM_AWS_LOGTAG, "Invalid service type '%s'. Valid one is '%s'", *nodes[i]->values, INSPECTOR_SERVICE_TYPE);
                    return OS_INVALID;
                }
            } else {
                mterror(WM_AWS_LOGTAG, "Attribute name '%s' is not valid. The valid one is '%s'.", *nodes[i]->attributes, XML_SERVICE_TYPE);
                return OS_INVALID;
            }

            // Expand service Child Nodes

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }

            mtdebug2(WM_AWS_LOGTAG, "Loop thru child nodes");
            for (j = 0; children[j]; j++) {

                mtdebug2(WM_AWS_LOGTAG, "Parse child node: %s", children[j]->element);

                if (!children[j]->element) {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                // Start
                if (!strcmp(children[j]->element, XML_AWS_ACCOUNT_ID)) {
                    if (strlen(children[j]->content) == 0) {
                        merror("Empty content for tag '%s' at module '%s'.", XML_SERVICE, WM_AWS_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                    free(cur_service->aws_account_id);
                    os_strdup(children[j]->content, cur_service->aws_account_id);
                } else if (!strcmp(children[j]->element, XML_ACCESS_KEY)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_service->access_key);
                        os_strdup(children[j]->content, cur_service->access_key);
                    }
                } else if (!strcmp(children[j]->element, XML_AWS_ACCOUNT_ALIAS)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_service->aws_account_alias);
                        os_strdup(children[j]->content, cur_service->aws_account_alias);
                    }
                } else if (!strcmp(children[j]->element, XML_SECRET_KEY)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_service->secret_key);
                        os_strdup(children[j]->content, cur_service->secret_key);
                    }
                } else if (!strcmp(children[j]->element, XML_AWS_PROFILE)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_service->aws_profile);
                        os_strdup(children[j]->content, cur_service->aws_profile);
                    }
                } else if (!strcmp(children[j]->element, XML_IAM_ROLE_ARN)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_service->iam_role_arn);
                        os_strdup(children[j]->content, cur_service->iam_role_arn);
                    }
                } else if (!strcmp(children[j]->element, XML_ONLY_LOGS_AFTER)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_service->only_logs_after);
                        os_strdup(children[j]->content, cur_service->only_logs_after);
                    }
                } else if (!strcmp(children[j]->element, XML_REGION)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_service->regions);
                        os_strdup(children[j]->content, cur_service->regions);
                    }
                } else {
                    merror("No such child tag '%s' of service at module '%s'.", children[j]->element, WM_AWS_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }

            OS_ClearNode(children);

        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_AWS_CONTEXT.name);
            return OS_INVALID;
        }
    }

    // Support legacy config
    if (aws_config->bucket) {
        mtwarn(WM_AWS_LOGTAG, "Deprecated config defined; please use current config definition at module '%s'.", WM_AWS_CONTEXT.name);

        // Create bucket node
        if (cur_bucket) {
            os_calloc(1, sizeof(wm_aws_bucket), cur_bucket->next);
            cur_bucket = cur_bucket->next;
        } else {
            // First bucket
            os_calloc(1, sizeof(wm_aws_bucket), cur_bucket);
            aws_config->buckets = cur_bucket;
        }

        if (aws_config->bucket) {
            if (strlen(aws_config->bucket) != 0) {
                free(cur_bucket->bucket);
                os_strdup(aws_config->bucket, cur_bucket->bucket);
            }
        }
        if (aws_config->secret_key) {
            if (strlen(aws_config->secret_key) != 0) {
                free(cur_bucket->secret_key);
                os_strdup(aws_config->secret_key, cur_bucket->secret_key);
            }
        }
        if (aws_config->access_key) {
            if (strlen(aws_config->access_key) != 0) {
                free(cur_bucket->access_key);
                os_strdup(aws_config->access_key, cur_bucket->access_key);
            }
        } else if (aws_config->remove_from_bucket) {
            cur_bucket->remove_from_bucket = aws_config->remove_from_bucket;
        }

        // Hard code LEGACY references
        free(cur_bucket->aws_account_alias);
        os_strdup(LEGACY_AWS_ACCOUNT_ALIAS, cur_bucket->aws_account_alias);
    }

    if (!aws_config->buckets && !aws_config->services) {
        mtwarn(WM_AWS_LOGTAG, "No buckets or services definitions found at module '%s'.", WM_AWS_CONTEXT.name);
        return OS_INVALID;
    }

    return 0;
}
