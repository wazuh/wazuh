/*
 * Wazuh Module for GitHub logs
 * Copyright (C) 2015, Wazuh Inc.
 * May 3, 2021.
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

STATIC void* wm_github_main(wm_github* github_config);    // Module main function. It won't return
STATIC void wm_github_destroy(wm_github* github_config);
STATIC void wm_github_auth_destroy(wm_github_auth* github_auth);
STATIC void wm_github_fail_destroy(wm_github_fail* github_fails);
cJSON *wm_github_dump(const wm_github* github_config);

/**
 * @brief Execute a scan
 * @param github_config GitHub configuration structure
 * @param initial_scan Whether it is the first scan or not
 */
STATIC void wm_github_execute_scan(wm_github *github_config, int initial_scan);

/**
 * @brief Get organization node from organizations failure list
 * @param fails Organizations failure list
 * @param org_name Organization name to search
 * @return Pointer to organization node if exists, NULL otherwise
 */
STATIC wm_github_fail* wm_github_get_fail_by_org(wm_github_fail *fails, char *org_name);

/**
 * @brief Increase failure counter for organization node and send failure message to manager if necessary
 * @param current_fails Organizations failure list
 * @param org_name Organization name to search
 * @param error_msg Error message to send
 * @param queue_fd Socket ID
 */
STATIC void wm_github_scan_failure_action(wm_github_fail **current_fails, char *org_name, char *error_msg, int queue_fd);

/* Context definition */
const wm_context WM_GITHUB_CONTEXT = {
    GITHUB_WM_NAME,
    (wm_routine)wm_github_main,
    (wm_routine)(void *)wm_github_destroy,
    (cJSON * (*)(const void *))wm_github_dump,
    NULL,
    NULL
};

void * wm_github_main(wm_github* github_config) {

    if (github_config->enabled) {
        mtinfo(WM_GITHUB_LOGTAG, "Module GitHub started.");

#ifndef WIN32
        // Connect to queue
        github_config->queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
        if (github_config->queue_fd < 0) {
            mterror(WM_GITHUB_LOGTAG, "Can't connect to queue. Closing module.");
            return NULL;
        }
#endif

        // Execute initial scan
        wm_github_execute_scan(github_config, 1);

        while (1) {
            sleep(github_config->interval);
            wm_github_execute_scan(github_config, 0);
            #ifdef WAZUH_UNIT_TESTING
                break;
            #endif
        }
    } else {
        mtinfo(WM_GITHUB_LOGTAG, "Module GitHub disabled.");
    }

    return NULL;
}

void wm_github_destroy(wm_github* github_config) {
    mtinfo(WM_GITHUB_LOGTAG, "Module GitHub finished.");
    wm_github_auth_destroy(github_config->auth);
    wm_github_fail_destroy(github_config->fails);
    os_free(github_config->event_type);
    os_free(github_config);
}

void wm_github_auth_destroy(wm_github_auth* github_auth)
{
    wm_github_auth* current = github_auth;
    wm_github_auth* next = NULL;
    while (current != NULL)
    {
        next = current->next;
        os_free(current->api_token);
        os_free(current->org_name);
        os_free(current);
        current = next;
    }
    github_auth = NULL;
}

void wm_github_fail_destroy(wm_github_fail* github_fails)
{
    wm_github_fail* current = github_fails;
    wm_github_fail* next = NULL;
    while (current != NULL)
    {
        next = current->next;
        os_free(current->org_name);
        os_free(current);
        current = next;
    }
    github_fails = NULL;
}

cJSON *wm_github_dump(const wm_github* github_config) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (github_config->enabled) {
        cJSON_AddStringToObject(wm_info, "enabled", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "enabled", "no");
    }
    if (github_config->only_future_events) {
        cJSON_AddStringToObject(wm_info, "only_future_events", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "only_future_events", "no");
    }
    if (github_config->interval) {
        cJSON_AddNumberToObject(wm_info, "interval", github_config->interval);
    }
    if (github_config->time_delay) {
        cJSON_AddNumberToObject(wm_info, "time_delay", github_config->time_delay);
    }
    if (github_config->curl_max_size) {
        cJSON_AddNumberToObject(wm_info, "curl_max_size", github_config->curl_max_size);
    }
    if (github_config->auth) {
        wm_github_auth *iter;
        cJSON *arr_auth = cJSON_CreateArray();
        for (iter = github_config->auth; iter; iter = iter->next) {
            cJSON *api_auth = cJSON_CreateObject();
            if (iter->org_name) {
                cJSON_AddStringToObject(api_auth, "org_name", iter->org_name);
            }
            if (iter->api_token) {
                cJSON_AddStringToObject(api_auth, "api_token", iter->api_token);
            }
            cJSON_AddItemToArray(arr_auth, api_auth);
        }
        if (cJSON_GetArraySize(arr_auth) > 0) {
            cJSON_AddItemToObject(wm_info, "api_auth", arr_auth);
        } else {
            cJSON_free(arr_auth);
        }
    }
    if (github_config->event_type) {
        cJSON_AddStringToObject(wm_info, "event_type", github_config->event_type);
    }
    cJSON_AddItemToObject(root, "github", wm_info);

    return root;
}

STATIC void wm_github_execute_scan(wm_github *github_config, int initial_scan) {
    int scan_finished = 0;
    int fail = 0;
    char **headers = NULL;
    char *payload = NULL;
    char *error_msg = NULL;
    char *next_page = NULL;
    char url[OS_SIZE_8192];
    char org_state_name[OS_SIZE_1024];
    time_t last_scan_time;
    time_t new_scan_time;
    curl_response *response;
    wm_github_auth* next = NULL;
    wm_github_fail *org_fail;
    wm_github_state org_state_struc;
    wm_github_auth* current = github_config->auth;

    while (current != NULL)
    {
        next = current->next;
        scan_finished = 0;
        fail = 0;
        mtdebug1(WM_GITHUB_LOGTAG, "Scanning organization: '%s'", current->org_name);

        memset(org_state_name, '\0', OS_SIZE_1024);
        snprintf(org_state_name, OS_SIZE_1024 -1, "%s-%s", WM_GITHUB_CONTEXT.name, current->org_name);

        memset(&org_state_struc, 0, sizeof(org_state_struc));

        // Load state for organization
        if (wm_state_io(org_state_name, WM_IO_READ, &org_state_struc, sizeof(org_state_struc)) < 0) {
            memset(&org_state_struc, 0, sizeof(org_state_struc));
        }

        new_scan_time = time(0) - github_config->time_delay;

        if (initial_scan && (!org_state_struc.last_log_time || github_config->only_future_events)) {
            org_state_struc.last_log_time = new_scan_time;
            if (wm_state_io(org_state_name, WM_IO_WRITE, &org_state_struc, sizeof(org_state_struc)) < 0) {
                mterror(WM_GITHUB_LOGTAG, "Couldn't save running state.");
            }
            current = next;
            continue;
        }

        last_scan_time = (time_t)org_state_struc.last_log_time + 1;

        char last_scan_time_str[80];
        memset(last_scan_time_str, '\0', 80);
        struct tm tm_last_scan = { .tm_sec = 0 };
        localtime_r(&last_scan_time, &tm_last_scan);
        strftime(last_scan_time_str, sizeof(last_scan_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_last_scan);

        char new_scan_time_str[80];
        memset(new_scan_time_str, '\0', 80);
        struct tm tm_new_scan = { .tm_sec = 0 };
        localtime_r(&new_scan_time, &tm_new_scan);
        strftime(new_scan_time_str, sizeof(new_scan_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_new_scan);

        memset(url, '\0', OS_SIZE_8192);
        snprintf(url, OS_SIZE_8192 -1, GITHUB_API_URL, current->org_name, last_scan_time_str, new_scan_time_str, github_config->event_type, ITEM_PER_PAGE);

        mtdebug1(WM_GITHUB_LOGTAG, "GitHub API URL: '%s'", url);

        char auth_header[OS_SIZE_8192];
        snprintf(auth_header, OS_SIZE_8192 -1, "Authorization: token %s", current->api_token);

        os_calloc(2, sizeof(char*), headers);
        headers[0] = auth_header;
        headers[1] = NULL;

        while (!scan_finished) {
            response = wurl_http_request(WURL_GET_METHOD, headers, url, NULL, github_config->curl_max_size);

            if (response) {
                if (response->max_size_reached) {
                    mtdebug1(WM_GITHUB_LOGTAG, "Libcurl error, reached maximum response size.");
                    scan_finished = 1;
                } else if (response->status_code == 200) {
                    // Load body to json and sent as localfile
                    cJSON *array_logs_json = NULL;

                    if (array_logs_json = cJSON_Parse(response->body), !array_logs_json) {
                        mtdebug1(WM_GITHUB_LOGTAG, "Error parsing response body.");
                        scan_finished = 1;
                        fail = 1;
                    } else {
                        int response_lenght = cJSON_GetArraySize(array_logs_json);

                        for (int i = 0 ; i < response_lenght ; i++) {
                            cJSON * subitem = cJSON_GetArrayItem(array_logs_json, i);

                            if (subitem) {
                                cJSON * github = cJSON_CreateObject();

                                cJSON_AddStringToObject(github, "integration", WM_GITHUB_CONTEXT.name);
                                cJSON_AddItemToObject(github, "github", cJSON_Duplicate(subitem, true));

                                payload = cJSON_PrintUnformatted(github);

                                mtdebug2(WM_GITHUB_LOGTAG, "Sending GitHub log: '%s'", payload);

                                if (wm_sendmsg(WM_GITHUB_MSG_DELAY, github_config->queue_fd, payload, WM_GITHUB_CONTEXT.name, LOCALFILE_MQ) < 0) {
                                    mterror(WM_GITHUB_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                                }

                                os_free(payload);
                                cJSON_Delete(github);
                            }
                        }

                        if (response_lenght == ITEM_PER_PAGE) {
                            next_page = wm_read_http_header_element(response->header, GITHUB_NEXT_PAGE_REGEX);
                            if ((next_page == NULL) || (strlen(next_page) >= OS_SIZE_8192)) {
                                scan_finished = 1;
                            } else {
                                snprintf(url, OS_SIZE_8192, "%s", next_page);
                                os_free(next_page);
                            }
                        } else {
                            scan_finished = 1;
                        }

                        cJSON_Delete(array_logs_json);
                    }
                } else {
                    if (response->body) {
                        os_strdup(response->body, error_msg);
                    }
                    scan_finished = 1;
                    fail = 1;
                }

                wurl_free_response(response);
            } else {
                scan_finished = 1;
                fail = 1;
            }
        }

        if (fail) {
            wm_github_scan_failure_action(&github_config->fails, current->org_name, error_msg, github_config->queue_fd);
        } else {
            org_state_struc.last_log_time = new_scan_time;
            if (wm_state_io(org_state_name, WM_IO_WRITE, &org_state_struc, sizeof(org_state_struc)) < 0) {
                mterror(WM_GITHUB_LOGTAG, "Couldn't save running state.");
            }

            org_fail = wm_github_get_fail_by_org(github_config->fails, current->org_name);
            if (org_fail != NULL) {
                org_fail->fails = 0;
            }
        }

        current = next;

        os_free(error_msg);
        os_free(headers);
    }
}

STATIC wm_github_fail* wm_github_get_fail_by_org(wm_github_fail *fails, char *org_name) {
    wm_github_fail* current;
    current = fails;
    int target_org = 0;

    while (!target_org)
    {
        if (current == NULL) {
            target_org = 1;
            continue;
        }

        if (strncmp(current->org_name, org_name, strlen(org_name)) != 0) {
            current = current->next;
        } else {
            target_org = 1;
        }
    }

    return current;
}

STATIC void wm_github_scan_failure_action(wm_github_fail **current_fails, char *org_name, char *error_msg, int queue_fd) {
    char *payload;
    wm_github_fail *org_fail;

    org_fail = wm_github_get_fail_by_org(*current_fails, org_name);

    if (org_fail == NULL) {
        os_calloc(1, sizeof(wm_github_fail), org_fail);

        if (*current_fails) {
            wm_github_fail *aux = *current_fails;

            while (aux->next) {
                aux = aux->next;
            }
            aux->next = org_fail;
        } else {
            // First wm_github_fail
            *current_fails = org_fail;
        }

        os_strdup(org_name, org_fail->org_name);

        org_fail->fails = 1;
    } else {
        org_fail->fails = org_fail->fails + 1;

        if (org_fail->fails == RETRIES_TO_SEND_ERROR) {
            // Send fail message
            cJSON *msg_obj = cJSON_Parse(error_msg);
            cJSON *fail_object = cJSON_CreateObject();
            cJSON *fail_github = cJSON_CreateObject();

            cJSON_AddStringToObject(fail_object, "actor", "wazuh");
            cJSON_AddStringToObject(fail_object, "organization", org_name);

            if (msg_obj) {
                payload = cJSON_PrintUnformatted(msg_obj);
                cJSON_AddStringToObject(fail_object, "response", payload);
                os_free(payload);
            } else {
                cJSON_AddStringToObject(fail_object, "response", "Unknown error");
            }

            cJSON_AddStringToObject(fail_github, "integration", WM_GITHUB_CONTEXT.name);
            cJSON_AddItemToObject(fail_github, "github", fail_object);

            payload = cJSON_PrintUnformatted(fail_github);

            mtdebug2(WM_GITHUB_LOGTAG, "Sending GitHub internal message: '%s'", payload);

            if (wm_sendmsg(WM_GITHUB_MSG_DELAY, queue_fd, payload, WM_GITHUB_CONTEXT.name, LOCALFILE_MQ) < 0) {
                mterror(WM_GITHUB_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
            }

            os_free(payload);
            cJSON_Delete(fail_github);
            cJSON_Delete(msg_obj);
        }
    }
}
#endif
