/*
 * Wazuh Module for Office365 events
 * Copyright (C) 2015, Wazuh Inc.
 * May 18, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#if defined(WIN32) || defined(__linux__) || defined(__MACH__)

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#ifdef WIN32
    #include "unit_tests/wrappers/wazuh/shared/url_wrappers.h"
#endif
#else
#define STATIC static
#endif

#include "wmodules.h"

#ifdef WIN32
#ifdef WAZUH_UNIT_TESTING
#define localtime_r(x, y)
#else
#define localtime_r(x, y) localtime_s(y, x)
#endif
#endif

STATIC void* wm_office365_main(wm_office365* office365_config);    // Module main function. It won't return
STATIC void wm_office365_destroy(wm_office365* office365_config);
STATIC void wm_office365_auth_destroy(wm_office365_auth* office365_auth);
STATIC void wm_office365_subscription_destroy(wm_office365_subscription* office365_subscription);
STATIC void wm_office365_fail_destroy(wm_office365_fail* office365_fails);
cJSON *wm_office365_dump(const wm_office365* office365_config);

/**
 * @brief Execute a scan
 * @param github_config Office365 configuration structure
 * @param initial_scan Whether it is the first scan or not
 */
STATIC void wm_office365_execute_scan(wm_office365* office365_config, int initial_scan);

/**
 * @brief Get access token through Office365 API
 * @param auth Office365 authentication node
 * @param max_size Max response size allowed
 * @return access_token if no error, NULL otherwise
 */
STATIC char* wm_office365_get_access_token(wm_office365_auth* auth, size_t max_size);

/**
 * @brief Start/stop a subscription through Office365 API
 * @param subscription Office365 subscription node
 * @param client_id Client ID
 * @param token Authentication token
 * @param start Whether to start/end a subscription
 * @param max_size Max response size allowed
 * @return 0 if no error, -1 otherwise
 */
STATIC int wm_office365_manage_subscription(wm_office365_subscription* subscription, const char* client_id, const char* token, int start, size_t max_size);

/**
 * @brief Get a content blob through Office365 API
 * @param url URL to request
 * @param token Authentication token
 * @param next_page Variable to store next page URL if exists
 * @param max_size Max response size allowed
 * @param buffer_size_reached Flag to set if max response size error happens
 * @return JSON content blob if no error, NULL otherwise
 */
STATIC cJSON* wm_office365_get_content_blobs(const char* url, const char* token, char** next_page, size_t max_size, bool* buffer_size_reached);

/**
 * @brief Get logs from content blob through Office365 API
 * @param url URL to request
 * @param token Authentication token
 * @param max_size Max response size allowed
 * @param buffer_size_reached Flag to set if max response size error happens
 * @return JSON logs if no error, NULL otherwise
 */
STATIC cJSON* wm_office365_get_logs_from_blob(const char* url, const char* token, size_t max_size, bool* buffer_size_reached);

/**
 * @brief Get tenant and subscription node from office365 failure list
 * @param fails Office365 failure list
 * @param tenant_id Tenant ID to search
 * @param subscription_name Subscription name to search
 * @return Pointer to tenant and subscription node if exists, NULL otherwise
 */
STATIC wm_office365_fail* wm_office365_get_fail_by_tenant_and_subscription(wm_office365_fail* fails, char* tenant_id, char* subscription_name);

/**
 * @brief Increase failure counter for tenant and subscription node and send failure message to manager if necessary
 * @param current_fails Office365 failure list
 * @param tenant_id Tenant ID to search
 * @param subscription_name Subscription name to search
 * @param queue_fd Socket ID
 */
STATIC void wm_office365_scan_failure_action(wm_office365_fail** current_fails, char* tenant_id, char* subscription_name, int queue_fd);

/* Context definition */
const wm_context WM_OFFICE365_CONTEXT = {
    OFFICE365_WM_NAME,
    (wm_routine)wm_office365_main,
    (wm_routine)(void *)wm_office365_destroy,
    (cJSON * (*)(const void *))wm_office365_dump,
    NULL,
    NULL
};

void * wm_office365_main(wm_office365* office365_config) {

    if (office365_config->enabled) {
        mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 started.");

#ifndef WIN32
        // Connect to queue
        office365_config->queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
        if (office365_config->queue_fd < 0) {
            mterror(WM_OFFICE365_LOGTAG, "Can't connect to queue. Closing module.");
            return NULL;
        }
#endif

        // Execute initial scan
        wm_office365_execute_scan(office365_config, 1);

        while (1) {
            sleep(office365_config->interval);
            wm_office365_execute_scan(office365_config, 0);
            #ifdef WAZUH_UNIT_TESTING
                break;
            #endif
        }
    } else {
        mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 disabled.");
    }

    return NULL;
}

void wm_office365_destroy(wm_office365* office365_config) {
    mtinfo(WM_OFFICE365_LOGTAG, "Module Office365 finished.");
    wm_office365_auth_destroy(office365_config->auth);
    wm_office365_subscription_destroy(office365_config->subscription);
    wm_office365_fail_destroy(office365_config->fails);
    os_free(office365_config);
}

void wm_office365_auth_destroy(wm_office365_auth* office365_auth) {
    wm_office365_auth* current = office365_auth;
    wm_office365_auth* next = NULL;
    while (current != NULL)
    {
        next = current->next;
        os_free(current->tenant_id);
        os_free(current->client_id);
        os_free(current->client_secret_path);
        os_free(current->client_secret);
        os_free(current);
        current = next;
    }
    office365_auth = NULL;
}

void wm_office365_subscription_destroy(wm_office365_subscription* office365_subscription) {
    wm_office365_subscription* current = office365_subscription;
    wm_office365_subscription* next = NULL;
    while (current != NULL)
    {
        next = current->next;
        os_free(current->subscription_name);
        os_free(current);
        current = next;
    }
    office365_subscription = NULL;
}

STATIC void wm_office365_fail_destroy(wm_office365_fail* office365_fails) {
    wm_office365_fail* current = office365_fails;
    wm_office365_fail* next = NULL;
    while (current != NULL)
    {
        next = current->next;
        os_free(current->tenant_id);
        os_free(current->subscription_name);
        os_free(current);
        current = next;
    }
    office365_fails = NULL;
}

cJSON *wm_office365_dump(const wm_office365* office365_config) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (office365_config->enabled) {
        cJSON_AddStringToObject(wm_info, "enabled", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "enabled", "no");
    }
    if (office365_config->only_future_events) {
        cJSON_AddStringToObject(wm_info, "only_future_events", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "only_future_events", "no");
    }
    if (office365_config->interval) {
        cJSON_AddNumberToObject(wm_info, "interval", office365_config->interval);
    }
    if (office365_config->curl_max_size) {
        cJSON_AddNumberToObject(wm_info, "curl_max_size", office365_config->curl_max_size);
    }
    if (office365_config->auth) {
        wm_office365_auth *iter;
        cJSON *arr_auth = cJSON_CreateArray();
        for (iter = office365_config->auth; iter; iter = iter->next) {
            cJSON *api_auth = cJSON_CreateObject();
            if (iter->tenant_id) {
                cJSON_AddStringToObject(api_auth, "tenant_id", iter->tenant_id);
            }
            if (iter->client_id) {
                cJSON_AddStringToObject(api_auth, "client_id", iter->client_id);
            }
            if (iter->client_secret_path) {
                cJSON_AddStringToObject(api_auth, "client_secret_path", iter->client_secret_path);
            }
            if (iter->client_secret) {
                cJSON_AddStringToObject(api_auth, "client_secret", iter->client_secret);
            }
            cJSON_AddItemToArray(arr_auth, api_auth);
        }
        if (cJSON_GetArraySize(arr_auth) > 0) {
            cJSON_AddItemToObject(wm_info, "api_auth", arr_auth);
        } else {
            cJSON_free(arr_auth);
        }
    }
    if (office365_config->subscription) {
        wm_office365_subscription *iter;
        cJSON *arr_subscription = cJSON_CreateArray();
        for (iter = office365_config->subscription; iter; iter = iter->next) {
            cJSON_AddItemToArray(arr_subscription, cJSON_CreateString(iter->subscription_name));
        }
        if (cJSON_GetArraySize(arr_subscription) > 0) {
            cJSON_AddItemToObject(wm_info, "subscriptions", arr_subscription);
        } else {
            cJSON_free(arr_subscription);
        }
    }

    cJSON_AddItemToObject(root, "office365", wm_info);

    return root;
}

STATIC void wm_office365_execute_scan(wm_office365* office365_config, int initial_scan) {
    int scan_finished = 0;
    int fail = 0;
    char url[OS_SIZE_8192];
    char tenant_state_name[OS_SIZE_1024];
    char *access_token = NULL;
    char *next_page = NULL;
    char *payload = NULL;
    time_t saved;
    time_t now;
    time_t start_time;
    time_t end_time;
    wm_office365_state tenant_state_struc;
    wm_office365_auth* next_auth = NULL;
    wm_office365_auth* current_auth = office365_config->auth;
    wm_office365_subscription* next_subscription = NULL;
    wm_office365_subscription* current_subscription = NULL;
    wm_office365_fail *tenant_fail = NULL;

    while (current_auth != NULL)
    {
        next_auth = current_auth->next;

        mtdebug1(WM_OFFICE365_LOGTAG, "Scanning tenant: '%s'", current_auth->tenant_id);

        // Get access token
        if (!initial_scan || !office365_config->only_future_events) {
            if (access_token = wm_office365_get_access_token(current_auth, office365_config->curl_max_size), !access_token) {
                wm_office365_scan_failure_action(&office365_config->fails, current_auth->tenant_id, NULL, office365_config->queue_fd);
                current_auth = next_auth;
                continue;
            } else {
                if (tenant_fail = wm_office365_get_fail_by_tenant_and_subscription(office365_config->fails,
                    current_auth->tenant_id, NULL), tenant_fail) {
                    tenant_fail->fails = 0;
                }
            }
        }

        next_subscription = NULL;
        current_subscription = office365_config->subscription;

        while (current_subscription != NULL)
        {
            next_subscription = current_subscription->next;

            memset(tenant_state_name, '\0', OS_SIZE_1024);
            snprintf(tenant_state_name, OS_SIZE_1024 -1, "%s-%s-%s", WM_OFFICE365_CONTEXT.name,
                current_auth->tenant_id, current_subscription->subscription_name);

            memset(&tenant_state_struc, 0, sizeof(tenant_state_struc));

            // Load state for tenant
            if (wm_state_io(tenant_state_name, WM_IO_READ, &tenant_state_struc, sizeof(tenant_state_struc)) < 0) {
                memset(&tenant_state_struc, 0, sizeof(tenant_state_struc));
            }

            now = time(0);

            if ((initial_scan && (!tenant_state_struc.last_log_time || office365_config->only_future_events)) ||
                (!initial_scan && !tenant_state_struc.last_log_time)) {
                tenant_state_struc.last_log_time = now;
                if (wm_state_io(tenant_state_name, WM_IO_WRITE, &tenant_state_struc, sizeof(tenant_state_struc)) < 0) {
                    mterror(WM_OFFICE365_LOGTAG, "Couldn't save running state.");
                }
                current_subscription = next_subscription;
                continue;
            }

            // Start subscription
            if (wm_office365_manage_subscription(current_subscription, current_auth->client_id, access_token, 1, office365_config->curl_max_size)) {
                wm_office365_scan_failure_action(&office365_config->fails, current_auth->tenant_id,
                    current_subscription->subscription_name, office365_config->queue_fd);
                current_subscription = next_subscription;
                continue;
            } else {
                if (tenant_fail = wm_office365_get_fail_by_tenant_and_subscription(office365_config->fails,
                    current_auth->tenant_id, current_subscription->subscription_name), tenant_fail) {
                    tenant_fail->fails = 0;
                }
            }

            saved = (time_t)tenant_state_struc.last_log_time;

            if (saved > 0 && saved < now) {
                start_time = saved;
            } else {
                start_time = now;
            }
            end_time = now;

            while ((end_time - start_time) > 0) {
                char start_time_str[80];
                memset(start_time_str, '\0', 80);
                struct tm tm_start = { .tm_sec = 0 };
                localtime_r(&start_time, &tm_start);
                strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_start);

                if ((end_time - start_time) > DAY_SEC) {
                    end_time = start_time + DAY_SEC;
                }

                char end_time_str[80];
                memset(end_time_str, '\0', 80);
                struct tm tm_end = { .tm_sec = 0 };
                localtime_r(&end_time, &tm_end);
                strftime(end_time_str, sizeof(end_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_end);

                memset(url, '\0', OS_SIZE_8192);
                snprintf(url, OS_SIZE_8192 -1, WM_OFFICE365_API_CONTENT_BLOB_URL, current_auth->client_id, current_subscription->subscription_name,
                    start_time_str, end_time_str);

                scan_finished = 0;
                fail = 0;

                while (!scan_finished) {
                    cJSON *blobs_array = NULL;
                    bool buffer_size_reached = false;

                    if (blobs_array = wm_office365_get_content_blobs(url, access_token, &next_page, office365_config->curl_max_size, &buffer_size_reached), blobs_array) {
                        int size_blobs = cJSON_GetArraySize(blobs_array);

                        for (int i = 0; !scan_finished && (i < size_blobs); i++) {
                            cJSON *blob = cJSON_GetArrayItem(blobs_array, i);
                            cJSON *content = cJSON_GetObjectItem(blob, "contentUri");

                            if (content && (content->type == cJSON_String)) {
                                cJSON *logs_array = NULL;

                                if (logs_array = wm_office365_get_logs_from_blob(content->valuestring, access_token, office365_config->curl_max_size, &buffer_size_reached), logs_array) {
                                    int size_logs = cJSON_GetArraySize(logs_array);

                                    for (int i = 0 ; i < size_logs ; i++) {
                                        cJSON *log = cJSON_GetArrayItem(logs_array, i);

                                        if (log) {
                                            cJSON *office365 = cJSON_CreateObject();

                                            cJSON_AddStringToObject(log, "Subscription", current_subscription->subscription_name);

                                            cJSON_AddStringToObject(office365, "integration", WM_OFFICE365_CONTEXT.name);
                                            cJSON_AddItemToObject(office365, "office365", cJSON_Duplicate(log, true));

                                            payload = cJSON_PrintUnformatted(office365);

                                            mtdebug2(WM_OFFICE365_LOGTAG, "Sending Office365 log: '%s'", payload);

                                            if (wm_sendmsg(WM_OFFICE365_MSG_DELAY, office365_config->queue_fd,
                                                payload, WM_OFFICE365_CONTEXT.name, LOCALFILE_MQ) < 0) {
                                                mterror(WM_OFFICE365_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                                            }

                                            os_free(payload);
                                            cJSON_Delete(office365);
                                        }
                                    }

                                    cJSON_Delete(logs_array);
                                } else {
                                    scan_finished = 1;
                                    if (!buffer_size_reached) {
                                        fail = 1;
                                    }
                                }
                            }
                        }

                        if (!scan_finished) {
                            if ((next_page == NULL) || (strlen(next_page) >= OS_SIZE_8192)) {
                                scan_finished = 1;
                            } else {
                                memset(url, '\0', OS_SIZE_8192);
                                strncpy(url, next_page, OS_SIZE_8192 - 1);
                                os_free(next_page);
                            }
                        }

                        cJSON_Delete(blobs_array);
                    } else {
                        scan_finished = 1;
                        if (!buffer_size_reached) {
                            fail = 1;
                        }
                    }
                }

                if (fail) {
                    wm_office365_scan_failure_action(&office365_config->fails, current_auth->tenant_id,
                        current_subscription->subscription_name, office365_config->queue_fd);
                    break;
                } else {
                    tenant_state_struc.last_log_time = end_time;
                    if (wm_state_io(tenant_state_name, WM_IO_WRITE, &tenant_state_struc, sizeof(tenant_state_struc)) < 0) {
                        mterror(WM_OFFICE365_LOGTAG, "Couldn't save running state.");
                    }

                    if (tenant_fail = wm_office365_get_fail_by_tenant_and_subscription(office365_config->fails,
                        current_auth->tenant_id, current_subscription->subscription_name), tenant_fail) {
                        tenant_fail->fails = 0;
                    }
                }

                start_time = end_time;
                end_time = now;
            }

            current_subscription = next_subscription;
        }

        current_auth = next_auth;

        os_free(access_token);
    }
}

STATIC char* wm_office365_get_access_token(wm_office365_auth* auth, size_t max_size) {
    char **headers = NULL;
    char url[OS_SIZE_8192];
    char auth_payload[OS_SIZE_8192];
    char auth_secret[OS_SIZE_1024];
    char *access_token = NULL;
    curl_response *response;

    memset(auth_secret, '\0', OS_SIZE_1024);
    if (auth->client_secret) {
        snprintf(auth_secret, OS_SIZE_1024 -1, "%s", auth->client_secret);
    } else if (auth->client_secret_path) {
        FILE *fd = NULL;

        if (fd = fopen(auth->client_secret_path, "r"), fd) {
            char str[OS_SIZE_1024 -1] = {0};
            size_t size_read = 0;

            if (size_read = fread(str, 1, OS_SIZE_1024 -2, fd), size_read > 0) {
                str[size_read] = '\0';
                snprintf(auth_secret, OS_SIZE_1024 -1, "%s", str);
            }
            fclose(fd);
        }
    }

    memset(auth_payload, '\0', OS_SIZE_8192);
    snprintf(auth_payload, OS_SIZE_8192 -1, WM_OFFICE365_API_ACCESS_TOKEN_PAYLOAD, auth->client_id, auth_secret);

    memset(url, '\0', OS_SIZE_8192);
    snprintf(url, OS_SIZE_8192 -1, WM_OFFICE365_API_ACCESS_TOKEN_URL, auth->tenant_id);

    mtdebug1(WM_OFFICE365_LOGTAG, "Office 365 API access token URL: '%s'", url);

    char auth_header[OS_SIZE_8192];
    snprintf(auth_header, OS_SIZE_8192 -1, "Content-Type: application/x-www-form-urlencoded");

    os_calloc(2, sizeof(char*), headers);
    headers[0] = auth_header;
    headers[1] = NULL;

    response = wurl_http_request(WURL_POST_METHOD, headers, url, auth_payload, max_size);

    if (response) {
        cJSON *response_json = NULL;

        if (response->max_size_reached) {
            mtdebug1(WM_OFFICE365_LOGTAG, "Libcurl error, reached maximum response size.");
        } else if (response_json = cJSON_Parse(response->body), response_json) {
            cJSON *access_token_json = cJSON_GetObjectItem(response_json, "access_token");

            if ((response->status_code == 200) && access_token_json && (access_token_json->type == cJSON_String)) {
                os_strdup(access_token_json->valuestring, access_token);
            } else {
                mtdebug1(WM_OFFICE365_LOGTAG, "Error while getting access token: '%s'", response->body);
            }
            cJSON_Delete(response_json);
        } else {
            mtdebug1(WM_OFFICE365_LOGTAG, "Error while parsing access token JSON response.");
        }
        wurl_free_response(response);
    } else {
        mtdebug1(WM_OFFICE365_LOGTAG, "Unknown error while getting access token.");
    }

    os_free(headers);

    return access_token;
}

STATIC int wm_office365_manage_subscription(wm_office365_subscription* subscription, const char* client_id, const char* token, int start, size_t max_size) {
    char **headers = NULL;
    char url[OS_SIZE_8192];
    curl_response *response;
    int ret_value = OS_INVALID;

    memset(url, '\0', OS_SIZE_8192);
    if (start) {
        snprintf(url, OS_SIZE_8192 -1, WM_OFFICE365_API_SUBSCRIPTION_URL, client_id, WM_OFFICE365_API_SUBSCRIPTION_START, subscription->subscription_name);
    } else {
        snprintf(url, OS_SIZE_8192 -1, WM_OFFICE365_API_SUBSCRIPTION_URL, client_id, WM_OFFICE365_API_SUBSCRIPTION_STOP, subscription->subscription_name);
    }

    mtdebug1(WM_OFFICE365_LOGTAG, "Office 365 API subscription URL: '%s'", url);

    char auth_header1[OS_SIZE_8192];
    snprintf(auth_header1, OS_SIZE_8192 -1, "Content-Type: application/json");

    char auth_header2[OS_SIZE_8192];
    snprintf(auth_header2, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    os_calloc(3, sizeof(char*), headers);
    headers[0] = auth_header1;
    headers[1] = auth_header2;
    headers[2] = NULL;

    response = wurl_http_request(WURL_POST_METHOD, headers, url, "", max_size);

    if (response) {
        cJSON *response_json = NULL;

        if (response->max_size_reached) {
            mtdebug1(WM_OFFICE365_LOGTAG, "Libcurl error, reached maximum response size.");
        } else if (response_json = cJSON_Parse(response->body), response_json) {
            cJSON *code_json = cJSON_GetObjectItem(cJSON_GetObjectItem(response_json, "error"), "code");

            if ((response->status_code == 200)
                || ((response->status_code == 400) && code_json && (code_json->type == cJSON_String) && !strncmp(code_json->valuestring, "AF20024", 7))) {
                // Error AF20024: The subscription is already enabled. No property change.
                ret_value = OS_SUCCESS;
            } else {
                mtdebug1(WM_OFFICE365_LOGTAG, "Error while managing subscription: '%s'", response->body);
            }
            cJSON_Delete(response_json);
        } else {
            mtdebug1(WM_OFFICE365_LOGTAG, "Error while parsing managing subscription JSON response.");
        }
        wurl_free_response(response);
    } else {
        mtdebug1(WM_OFFICE365_LOGTAG, "Unknown error while managing subscription.");
    }

    os_free(headers);

    return ret_value;
}

STATIC cJSON* wm_office365_get_content_blobs(const char* url, const char* token, char** next_page, size_t max_size, bool* buffer_size_reached) {
    char **headers = NULL;
    curl_response *response;
    cJSON *blobs_array = NULL;

    mtdebug1(WM_OFFICE365_LOGTAG, "Office 365 API content blobs URL: '%s'", url);

    char auth_header1[OS_SIZE_8192];
    snprintf(auth_header1, OS_SIZE_8192 -1, "Content-Type: application/json");

    char auth_header2[OS_SIZE_8192];
    snprintf(auth_header2, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    os_calloc(3, sizeof(char*), headers);
    headers[0] = auth_header1;
    headers[1] = auth_header2;
    headers[2] = NULL;

    response = wurl_http_request(WURL_GET_METHOD, headers, url, "", max_size);

    if (response) {
        cJSON *response_json = NULL;

        if (response->max_size_reached) {
            *buffer_size_reached = true;
            mtdebug1(WM_OFFICE365_LOGTAG, "Libcurl error, reached maximum response size.");
        } else if (response_json = cJSON_Parse(response->body), response_json) {
            cJSON *code_json = cJSON_GetObjectItem(cJSON_GetObjectItem(response_json, "error"), "code");

            if ((response->status_code == 200) && (response_json->type == cJSON_Array)) {
                blobs_array = cJSON_Duplicate(response_json, true);

                if (cJSON_GetArraySize(blobs_array) > 0) {
                    *next_page = wm_read_http_header_element(response->header, WM_OFFICE365_NEXT_PAGE_REGEX);
                }
            } else if ((response->status_code == 400) && code_json && (code_json->type == cJSON_String) && !strncmp(code_json->valuestring, "AF20055", 7)) {
                // Error AF20055: Start time and end time must both be specified (or both omitted) and must be less than or equal to 24 hours apart,
                // with the start time prior to end time and start time no more than 7 days in the past.
                blobs_array = cJSON_CreateArray();
            } else {
                mtdebug1(WM_OFFICE365_LOGTAG, "Error while getting content blobs: '%s'", response->body);
            }
            cJSON_Delete(response_json);
        } else {
            mtdebug1(WM_OFFICE365_LOGTAG, "Error while parsing content blobs JSON response.");
        }
        wurl_free_response(response);
    } else {
        mtdebug1(WM_OFFICE365_LOGTAG, "Unknown error while getting content blobs.");
    }

    os_free(headers);

    return blobs_array;
}

STATIC cJSON* wm_office365_get_logs_from_blob(const char* url, const char* token, size_t max_size, bool* buffer_size_reached) {
    char **headers = NULL;
    curl_response *response;
    cJSON *logs_array = NULL;

    mtdebug1(WM_OFFICE365_LOGTAG, "Office 365 API content URI: '%s'", url);

    char auth_header1[OS_SIZE_8192];
    snprintf(auth_header1, OS_SIZE_8192 -1, "Content-Type: application/json");

    char auth_header2[OS_SIZE_8192];
    snprintf(auth_header2, OS_SIZE_8192 -1, "Authorization: Bearer %s", token);

    os_calloc(3, sizeof(char*), headers);
    headers[0] = auth_header1;
    headers[1] = auth_header2;
    headers[2] = NULL;

    response = wurl_http_request(WURL_GET_METHOD, headers, url, "", max_size);

    if (response) {
        cJSON *response_json = NULL;

        if (response->max_size_reached) {
            *buffer_size_reached = true;
            mtdebug1(WM_OFFICE365_LOGTAG, "Libcurl error, reached maximum response size.");
        } else if (response_json = cJSON_Parse(response->body), response_json) {
            if ((response->status_code == 200) && (response_json->type == cJSON_Array)) {
                logs_array = cJSON_Duplicate(response_json, true);
            } else {
                mtdebug1(WM_OFFICE365_LOGTAG, "Error while getting logs from blob: '%s'", response->body);
            }
            cJSON_Delete(response_json);
        } else {
            mtdebug1(WM_OFFICE365_LOGTAG, "Error while parsing logs from blob JSON response.");
        }
        wurl_free_response(response);
    } else {
        mtdebug1(WM_OFFICE365_LOGTAG, "Unknown error while getting logs from blob.");
    }

    os_free(headers);

    return logs_array;
}

STATIC wm_office365_fail* wm_office365_get_fail_by_tenant_and_subscription(wm_office365_fail* fails, char* tenant_id, char* subscription_name) {
    wm_office365_fail* current;
    current = fails;
    int target_tenant = 0;

    while (!target_tenant)
    {
        if (current == NULL) {
            target_tenant = 1;
            continue;
        }

        if (!strncmp(current->tenant_id, tenant_id, strlen(tenant_id)) && ((!subscription_name && !current->subscription_name) ||
            (subscription_name && current->subscription_name && !strncmp(current->subscription_name, subscription_name, strlen(subscription_name))))) {
            target_tenant = 1;
        } else {
            current = current->next;
        }
    }

    return current;
}

STATIC void wm_office365_scan_failure_action(wm_office365_fail** current_fails, char* tenant_id, char* subscription_name, int queue_fd) {
    char *payload;
    wm_office365_fail *tenant_fail = NULL;

    if (tenant_fail = wm_office365_get_fail_by_tenant_and_subscription(*current_fails, tenant_id, subscription_name), !tenant_fail) {
        os_calloc(1, sizeof(wm_office365_fail), tenant_fail);

        if (*current_fails) {
            wm_office365_fail *aux = *current_fails;

            while (aux->next) {
                aux = aux->next;
            }
            aux->next = tenant_fail;
        } else {
            // First wm_office365_fail
            *current_fails = tenant_fail;
        }

        os_strdup(tenant_id, tenant_fail->tenant_id);
        if (subscription_name) {
            os_strdup(subscription_name, tenant_fail->subscription_name);
        }

        tenant_fail->fails = 1;
    } else {
        tenant_fail->fails = tenant_fail->fails + 1;

        if (tenant_fail->fails == WM_OFFICE365_RETRIES_TO_SEND_ERROR) {
            // Send fail message
            cJSON *fail_object = cJSON_CreateObject();
            cJSON *fail_office365 = cJSON_CreateObject();

            cJSON_AddStringToObject(fail_object, "actor", "wazuh");
            cJSON_AddStringToObject(fail_object, "tenant_id", tenant_id);
            if (subscription_name) {
                cJSON_AddStringToObject(fail_object, "subscription_name", subscription_name);
            }

            cJSON_AddStringToObject(fail_office365, "integration", WM_OFFICE365_CONTEXT.name);
            cJSON_AddItemToObject(fail_office365, "office365", fail_object);

            payload = cJSON_PrintUnformatted(fail_office365);

            mtdebug2(WM_OFFICE365_LOGTAG, "Sending Office365 internal message: '%s'", payload);

            if (wm_sendmsg(WM_OFFICE365_MSG_DELAY, queue_fd, payload, WM_OFFICE365_CONTEXT.name, LOCALFILE_MQ) < 0) {
                mterror(WM_OFFICE365_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
            }

            os_free(payload);
            cJSON_Delete(fail_office365);
        }
    }
}
#endif
