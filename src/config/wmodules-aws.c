/*
 * Wazuh Module Configuration
 * Copyright (C) 2015, Wazuh Inc.
 * October 26, 2017.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wazuh_modules/wmodules.h"

static const char *XML_DISABLED = "disabled";
static const char *XML_BUCKET = "bucket";
static const char *XML_SERVICE = "service";
static const char *XML_SUBSCRIBER = "subscriber";
static const char *XML_SUBSCRIBER_TYPE = "type";
static const char *XML_SUBSCRIBER_QUEUE = "sqs_name";
static const char *XML_ACCESS_KEY = "access_key";
static const char *XML_SECRET_KEY = "secret_key";
static const char *XML_RUN_ON_START = "run_on_start";
static const char *XML_REMOVE_FORM_BUCKET = "remove_from_bucket";
static const char *XML_SKIP_ON_ERROR = "skip_on_error";
static const char *XML_AWS_PROFILE = "aws_profile";
static const char *XML_AWS_EXTERNAL_ID = "external_id";
static const char *XML_IAM_ROLE_ARN = "iam_role_arn";
static const char *XML_AWS_ORGANIZATION_ID = "aws_organization_id";
static const char *XML_AWS_ACCOUNT_ID = "aws_account_id";
static const char *XML_AWS_ACCOUNT_ALIAS = "aws_account_alias";
static const char *XML_TRAIL_PREFIX = "path";
static const char *XML_TRAIL_SUFFIX = "path_suffix";
static const char *XML_ONLY_LOGS_AFTER = "only_logs_after";
static const char *XML_REGION = "regions";
static const char *XML_LOG_GROUP = "aws_log_groups";
static const char *XML_REMOVE_LOG_STREAMS = "remove_log_streams";
static const char *XML_DISCARD_FIELD = "field";
static const char *XML_DISCARD_REGEX = "discard_regex";
static const char *XML_STS_ENDPOINT = "sts_endpoint";
static const char *XML_SERVICE_ENDPOINT = "service_endpoint";
static const char *XML_BUCKET_TYPE = "type";
static const char *XML_SERVICE_TYPE = "type";
static const char *XML_BUCKET_NAME = "name";
static const char *XML_IAM_ROLE_DURATION = "iam_role_duration";

static const char *LEGACY_AWS_ACCOUNT_ALIAS = "LEGACY";

static const char *CLOUDTRAIL_BUCKET_TYPE = "cloudtrail";
static const char *ALB_BUCKET_TYPE = "alb";
static const char *CLB_BUCKET_TYPE = "clb";
static const char *NLB_BUCKET_TYPE = "nlb";
static const char *CONFIG_BUCKET_TYPE = "config";
static const char *VPCFLOW_BUCKET_TYPE = "vpcflow";
static const char *CUSTOM_BUCKET_TYPE = "custom";
static const char *GUARDDUTY_BUCKET_TYPE = "guardduty";
static const char *WAF_BUCKET_TYPE = "waf";
static const char *SERVER_ACCESS_BUCKET_TYPE = "server_access";
static const char *INSPECTOR_SERVICE_TYPE = "inspector";
static const char *CLOUDWATCHLOGS_SERVICE_TYPE = "cloudwatchlogs";
static const char *CISCO_UMBRELLA_BUCKET_TYPE = "cisco_umbrella";
static const char *SECURITY_LAKE_SUBSCRIBER_TYPE = "security_lake";
static const char *BUCKETS_SUBSCRIBER_TYPE = "buckets";
static const char *SECURITY_HUB_SUBSCRIBER_TYPE = "security_hub";

static const char *AUTHENTICATION_OPTIONS_URL = "https://documentation.wazuh.com/current/amazon/services/prerequisites/credentials.html";
static const char *DEPRECATED_MESSAGE = "Deprecated tag <%s> found at module '%s'. This tag was deprecated in %s; please use a different authentication method. Check %s for more information.";

// Parse XML

int wm_aws_read(const OS_XML *xml, xml_node **nodes, wmodule *module)
{
    int i = 0;
    int j = 0;
    xml_node **children = NULL;
    wm_aws *aws_config;
    wm_aws_bucket *cur_bucket = NULL;
    wm_aws_service *cur_service = NULL;
    wm_aws_subscriber *cur_subscriber = NULL;

    if (!nodes) {
        merror("Tag <%s> not found at module '%s'.", XML_BUCKET, WM_AWS_CONTEXT.name);
        return OS_INVALID;
    }

    // Create module

    os_calloc(1, sizeof(wm_aws), aws_config);
    aws_config->enabled = 1;
    aws_config->run_on_start = 1;
    aws_config->remove_from_bucket = 0;
    sched_scan_init(&(aws_config->scan_config));
    aws_config->scan_config.interval = WM_AWS_DEFAULT_INTERVAL;
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
                        || !strcmp(*nodes[i]->values, VPCFLOW_BUCKET_TYPE) || !strcmp(*nodes[i]->values, CISCO_UMBRELLA_BUCKET_TYPE)
                        || !strcmp(*nodes[i]->values, WAF_BUCKET_TYPE) || !strcmp(*nodes[i]->values, ALB_BUCKET_TYPE)
                        || !strcmp(*nodes[i]->values, CLB_BUCKET_TYPE) || !strcmp(*nodes[i]->values, NLB_BUCKET_TYPE)
                        || !strcmp(*nodes[i]->values, SERVER_ACCESS_BUCKET_TYPE)) {
                        os_strdup(*nodes[i]->values, cur_bucket->type);
                    } else {
                        mterror(WM_AWS_LOGTAG, "Invalid bucket type '%s'. Valid ones are '%s', '%s', '%s', '%s', '%s', "
                                               "'%s', %s', %s', %s', %s' or '%s'",
                            *nodes[i]->values, CLOUDTRAIL_BUCKET_TYPE, CONFIG_BUCKET_TYPE, GUARDDUTY_BUCKET_TYPE, VPCFLOW_BUCKET_TYPE,
                            WAF_BUCKET_TYPE, CISCO_UMBRELLA_BUCKET_TYPE, CUSTOM_BUCKET_TYPE, ALB_BUCKET_TYPE, CLB_BUCKET_TYPE, NLB_BUCKET_TYPE,
                            SERVER_ACCESS_BUCKET_TYPE);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else {
                    mterror(WM_AWS_LOGTAG, "Attribute name '%s' is not valid. The valid one is '%s'.", *nodes[i]->attributes, XML_BUCKET_TYPE);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                mtdebug2(WM_AWS_LOGTAG, "Loop through child nodes");
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
                    } else if (!strcmp(children[j]->element, XML_AWS_ORGANIZATION_ID)) {
                        if (strlen(children[j]->content) == 0) {
                            merror("Empty content for tag '%s' at module '%s'.", XML_BUCKET, WM_AWS_CONTEXT.name);
                            OS_ClearNode(children);
                            return OS_INVALID;
                        }
                        free(cur_bucket->aws_organization_id);
                        os_strdup(children[j]->content, cur_bucket->aws_organization_id);
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
                            mwarn(DEPRECATED_MESSAGE, children[j]->element, WM_AWS_CONTEXT.name, "4.4", AUTHENTICATION_OPTIONS_URL);
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
                            mwarn(DEPRECATED_MESSAGE, children[j]->element, WM_AWS_CONTEXT.name, "4.4", AUTHENTICATION_OPTIONS_URL);
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
                    } else if (!strcmp(children[j]->element, XML_IAM_ROLE_DURATION)){
                        if (strlen(children[j]->content) != 0){
                            free(cur_bucket->iam_role_duration);
                            os_strdup(children[j]->content, cur_bucket->iam_role_duration);
                        }
                    } else if (!strcmp(children[j]->element, XML_TRAIL_PREFIX)) {
                        if (strlen(children[j]->content) == 0) {
                            mwarn("Empty content for tag '%s' at module '%s'.", XML_TRAIL_PREFIX, WM_AWS_CONTEXT.name);
                        }
                        else if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->trail_prefix);
                            os_strdup(children[j]->content, cur_bucket->trail_prefix);
                        }
                    } else if (!strcmp(children[j]->element, XML_TRAIL_SUFFIX)) {
                        if (strlen(children[j]->content) == 0) {
                            mwarn("Empty content for tag '%s' at module '%s'.", XML_TRAIL_SUFFIX, WM_AWS_CONTEXT.name);
                        }
                        else if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->trail_suffix);
                            os_strdup(children[j]->content, cur_bucket->trail_suffix);
                        }
                    } else if (!strcmp(children[j]->element, XML_ONLY_LOGS_AFTER)) {
                        if (strlen(children[j]->content) == 0) {
                            mwarn("Empty content for tag '%s' at module '%s'.", XML_ONLY_LOGS_AFTER, WM_AWS_CONTEXT.name);
                        }
                        else if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->only_logs_after);
                            os_strdup(children[j]->content, cur_bucket->only_logs_after);
                        }
                    } else if (!strcmp(children[j]->element, XML_REGION)) {
                        if (strlen(children[j]->content) == 0) {
                            mwarn("Empty content for tag '%s' at module '%s'.", XML_REGION, WM_AWS_CONTEXT.name);
                        }
                        else if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->regions);
                            os_strdup(children[j]->content, cur_bucket->regions);
                        }
                    } else if (strcmp(children[j]->element, XML_DISCARD_REGEX) == 0) {
                        if (strlen(children[j]->content) != 0) {
                            const char * field_attr = w_get_attr_val_by_name(children[j], XML_DISCARD_FIELD);
                            if ((field_attr) && (strlen(field_attr) != 0)) {
                                free(cur_bucket->discard_field);
                                os_strdup(field_attr, cur_bucket->discard_field);

                                free(cur_bucket->discard_regex);
                                os_strdup(children[j]->content, cur_bucket->discard_regex);
                            } else {
                                merror("Required attribute '%s' is missing in '%s'. This is a mandatory parameter.", XML_DISCARD_FIELD, XML_DISCARD_REGEX);
                                OS_ClearNode(children);
                                return OS_INVALID;
                            }
                        } else {
                            mwarn("No value was provided for '%s'. No event will be skipped.", XML_DISCARD_REGEX);
                        }
                    } else if (!strcmp(children[j]->element, XML_STS_ENDPOINT)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->sts_endpoint);
                            os_strdup(children[j]->content, cur_bucket->sts_endpoint);
                        }
                    } else if (!strcmp(children[j]->element, XML_SERVICE_ENDPOINT)) {
                        if (strlen(children[j]->content) != 0) {
                            free(cur_bucket->service_endpoint);
                            os_strdup(children[j]->content, cur_bucket->service_endpoint);
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
                    mterror(WM_AWS_LOGTAG, "Empty service type. Valid ones are '%s' or '%s'", INSPECTOR_SERVICE_TYPE, CLOUDWATCHLOGS_SERVICE_TYPE);
                    return OS_INVALID;
                } else if (!strcmp(*nodes[i]->values, INSPECTOR_SERVICE_TYPE) || !strcmp(*nodes[i]->values, CLOUDWATCHLOGS_SERVICE_TYPE)) {
                    os_strdup(*nodes[i]->values, cur_service->type);
                } else {
                    mterror(WM_AWS_LOGTAG, "Invalid service type '%s'. Valid ones are '%s' or '%s'", *nodes[i]->values, INSPECTOR_SERVICE_TYPE, CLOUDWATCHLOGS_SERVICE_TYPE);
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

            mtdebug2(WM_AWS_LOGTAG, "Loop through child nodes");
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
                        mwarn(DEPRECATED_MESSAGE, children[j]->element, WM_AWS_CONTEXT.name, "4.4", AUTHENTICATION_OPTIONS_URL);
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
                        mwarn(DEPRECATED_MESSAGE, children[j]->element, WM_AWS_CONTEXT.name, "4.4", AUTHENTICATION_OPTIONS_URL);
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
                } else if (!strcmp(children[j]->element, XML_IAM_ROLE_DURATION)){
                        if (strlen(children[j]->content) != 0){
                            free(cur_service->iam_role_duration);
                            os_strdup(children[j]->content, cur_service->iam_role_duration);
                        }
                } else if (!strcmp(children[j]->element, XML_ONLY_LOGS_AFTER)) {
                    if (strlen(children[j]->content) == 0) {
                            mwarn("Empty content for tag '%s' at module '%s'.", XML_ONLY_LOGS_AFTER, WM_AWS_CONTEXT.name);
                    }
                    else if (strlen(children[j]->content) != 0) {
                        free(cur_service->only_logs_after);
                        os_strdup(children[j]->content, cur_service->only_logs_after);
                    }
                } else if (!strcmp(children[j]->element, XML_REGION)) {
                    if (strlen(children[j]->content) == 0) {
                            mwarn("Empty content for tag '%s' at module '%s'.", XML_REGION, WM_AWS_CONTEXT.name);
                    }
                    else if (strlen(children[j]->content) != 0) {
                        free(cur_service->regions);
                        os_strdup(children[j]->content, cur_service->regions);
                    }
                } else if (!strcmp(children[j]->element, XML_LOG_GROUP)) {
                    if (strlen(children[j]->content) == 0) {
                            merror("Empty content for tag '%s' at module '%s'.", XML_LOG_GROUP, WM_AWS_CONTEXT.name);
                            OS_ClearNode(children);
                            return OS_INVALID;
                        }
                    else if (strlen(children[j]->content) != 0) {
                        free(cur_service->aws_log_groups);
                        os_strdup(children[j]->content, cur_service->aws_log_groups);
                    }
                } else if (!strcmp(children[j]->element, XML_REMOVE_LOG_STREAMS)) {
                    if (!strcmp(children[j]->content, "yes")) {
                        cur_service->remove_log_streams = 1;
                    } else if (!strcmp(children[j]->content, "no")) {
                        cur_service->remove_log_streams = 0;
                    } else {
                        merror("Invalid content for tag '%s' at module '%s'.", XML_REMOVE_LOG_STREAMS, WM_AWS_CONTEXT.name);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                } else if (strcmp(children[j]->element, XML_DISCARD_REGEX) == 0) {
                    if (strlen(children[j]->content) != 0) {
                        const char * field_attr = w_get_attr_val_by_name(children[j], XML_DISCARD_FIELD);
                        if ((field_attr) && (strlen(field_attr) != 0)) {
                            free(cur_service->discard_field);
                            os_strdup(field_attr, cur_service->discard_field);

                            free(cur_service->discard_regex);
                            os_strdup(children[j]->content, cur_service->discard_regex);
                        } else {
                             if(strcmp(*nodes[i]->values, CLOUDWATCHLOGS_SERVICE_TYPE) == 0){
                                free(cur_service->discard_regex);
                                os_strdup(children[j]->content, cur_service->discard_regex);
                            } else {
                                merror("Required attribute '%s' is missing in '%s'. This is a mandatory parameter.", XML_DISCARD_FIELD, XML_DISCARD_REGEX);
                                OS_ClearNode(children);
                                return OS_INVALID;
                            }
                        }
                    } else {
                        mwarn("No value was provided for '%s'. No event will be skipped.", XML_DISCARD_REGEX);
                    }
                } else if (!strcmp(children[j]->element, XML_STS_ENDPOINT)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_service->sts_endpoint);
                        os_strdup(children[j]->content, cur_service->sts_endpoint);
                    }
                } else if (!strcmp(children[j]->element, XML_SERVICE_ENDPOINT)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_service->service_endpoint);
                        os_strdup(children[j]->content, cur_service->service_endpoint);
                    }
                } else {
                    merror("No such child tag '%s' of service at module '%s'.", children[j]->element, WM_AWS_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }

            OS_ClearNode(children);

        // for subscriber
        } else if (!strcmp(nodes[i]->element, XML_SUBSCRIBER)) {

            mtdebug2(WM_AWS_LOGTAG, "Found a subscriber tag");

            if (!nodes[i]->attributes) {
                mterror(WM_AWS_LOGTAG, "Undefined type for subscriber.");
                return OS_INVALID;
            }

            // Create subscriber node
            if (cur_subscriber) {
                os_calloc(1, sizeof(wm_aws_subscriber), cur_subscriber->next);
                cur_subscriber = cur_subscriber->next;
                mtdebug2(WM_AWS_LOGTAG, "Creating another subscriber structure");
            } else {
                // First subscriber
                os_calloc(1, sizeof(wm_aws_subscriber), cur_subscriber);
                aws_config->subscribers = cur_subscriber;
                mtdebug2(WM_AWS_LOGTAG, "Creating first subscriber structure");
            }

            // type is an attribute of the subscriber tag
            if (!strcmp(*nodes[i]->attributes, XML_SUBSCRIBER_TYPE)) {
                if (!nodes[i]->values) {
                    mterror(WM_AWS_LOGTAG, "Empty subscriber type. Valid ones are '%s', '%s' or '%s'",
                        SECURITY_LAKE_SUBSCRIBER_TYPE, BUCKETS_SUBSCRIBER_TYPE, SECURITY_HUB_SUBSCRIBER_TYPE);
                    return OS_INVALID;
                } else if (!strcmp(*nodes[i]->values, SECURITY_LAKE_SUBSCRIBER_TYPE) || !strcmp(*nodes[i]->values, BUCKETS_SUBSCRIBER_TYPE) || !strcmp(*nodes[i]->values, SECURITY_HUB_SUBSCRIBER_TYPE)) {
                    os_strdup(*nodes[i]->values, cur_subscriber->type);
                } else {
                    mterror(WM_AWS_LOGTAG, "Invalid subscriber type '%s'. Valid ones are '%s', '%s' or '%s'",
                        *nodes[i]->values, SECURITY_LAKE_SUBSCRIBER_TYPE, BUCKETS_SUBSCRIBER_TYPE,
                        SECURITY_HUB_SUBSCRIBER_TYPE);
                    return OS_INVALID;
                }
            } else {
                mterror(WM_AWS_LOGTAG, "Attribute name '%s' is not valid. The valid one is '%s'.", *nodes[i]->attributes, XML_SUBSCRIBER_TYPE);
                return OS_INVALID;
            }

            // Expand subscriber Child Nodes

            if (!(children = OS_GetElementsbyNode(xml, nodes[i]))) {
                continue;
            }

            mtdebug2(WM_AWS_LOGTAG, "Loop through child nodes");
            for (j = 0; children[j]; j++) {

                mtdebug2(WM_AWS_LOGTAG, "Parse child node: %s", children[j]->element);

                if (!children[j]->element) {
                    merror(XML_ELEMNULL);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }

                // Start
                if (strcmp(children[j]->element, XML_SUBSCRIBER_QUEUE) == 0) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_subscriber->sqs_name);
                        os_strdup(children[j]->content, cur_subscriber->sqs_name);
                    } else {
                         // If the value is empty, raise error
                         merror("Invalid content for tag '%s': It cannot be empty", XML_SUBSCRIBER_QUEUE);
                         OS_ClearNode(children);
                         return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->element, XML_AWS_EXTERNAL_ID)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_subscriber->external_id);
                        os_strdup(children[j]->content, cur_subscriber->external_id);
                    } else {
                         // If the value is empty, raise error
                         merror("Invalid content for tag '%s': It cannot be empty", XML_AWS_EXTERNAL_ID);
                         OS_ClearNode(children);
                         return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->element, XML_IAM_ROLE_ARN)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_subscriber->iam_role_arn);
                        os_strdup(children[j]->content, cur_subscriber->iam_role_arn);
                    } else {
                         // If the value is empty, raise error
                         merror("Invalid content for tag '%s': It cannot be empty", XML_IAM_ROLE_ARN);
                         OS_ClearNode(children);
                         return OS_INVALID;
                    }
                } else if (!strcmp(children[j]->element, XML_IAM_ROLE_DURATION)){
                        if (strlen(children[j]->content) != 0){
                            free(cur_subscriber->iam_role_duration);
                            os_strdup(children[j]->content, cur_subscriber->iam_role_duration);
                        }
                } else if (!strcmp(children[j]->element, XML_STS_ENDPOINT)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_subscriber->sts_endpoint);
                        os_strdup(children[j]->content, cur_subscriber->sts_endpoint);
                    }
                } else if (!strcmp(children[j]->element, XML_SERVICE_ENDPOINT)) {
                    if (strlen(children[j]->content) != 0) {
                        free(cur_subscriber->service_endpoint);
                        os_strdup(children[j]->content, cur_subscriber->service_endpoint);
                    }
                } else if (!strcmp(children[j]->element, XML_AWS_PROFILE)) {
                     if (strlen(children[j]->content) != 0)  {
                        free(cur_subscriber->aws_profile);
                        os_strdup(children[j]->content, cur_subscriber->aws_profile);
                     }
                } else if (strcmp(children[j]->element, XML_DISCARD_REGEX) == 0) {
                    if (strcmp(*nodes[i]->values, SECURITY_LAKE_SUBSCRIBER_TYPE) == 0) {
                        merror("The '%s' parameter is not available for Security Lake.", XML_DISCARD_REGEX);
                        OS_ClearNode(children);
                        return OS_INVALID;
                    }
                    if (strlen(children[j]->content) != 0) {
                        const char * field_attr = w_get_attr_val_by_name(children[j], XML_DISCARD_FIELD);
                        if ((field_attr) && (strlen(field_attr) != 0)) {
                            free(cur_subscriber->discard_field);
                            os_strdup(field_attr, cur_subscriber->discard_field);

                            free(cur_subscriber->discard_regex);
                            os_strdup(children[j]->content, cur_subscriber->discard_regex);
                        } else {
                            free(cur_subscriber->discard_regex);
                            os_strdup(children[j]->content, cur_subscriber->discard_regex);
                            }
                    } else {
                        mwarn("No value was provided for '%s'. No event will be skipped.", XML_DISCARD_REGEX);
                    }
                } else {
                    merror("No such child tag '%s' of service at module '%s'.", children[j]->element, WM_AWS_CONTEXT.name);
                    OS_ClearNode(children);
                    return OS_INVALID;
                }
            }

            OS_ClearNode(children);

        } else if (is_sched_tag(nodes[i]->element)) {
            // Do nothing
        } else {
            merror("No such tag '%s' at module '%s'.", nodes[i]->element, WM_AWS_CONTEXT.name);
            return OS_INVALID;
        }
    }

    const int sched_read = sched_scan_read(&(aws_config->scan_config), nodes, module->context->name);
    if ( sched_read != 0 ) {
        return OS_INVALID;
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

    if (!aws_config->buckets && !aws_config->services  && !aws_config->subscribers) {
        mtwarn(WM_AWS_LOGTAG, "No buckets, services or subscribers definitions found at module '%s'.", WM_AWS_CONTEXT.name);
        return OS_INVALID;
    }

    return 0;
}