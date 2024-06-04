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
    #include "../unit_tests/wrappers/wazuh/shared/url_wrappers.h"
#endif
#else
#define STATIC static
#endif

#include "wmodules.h"

#ifdef WIN32
#ifdef WAZUH_UNIT_TESTING
#define gmtime_r(x, y)
#else
#define gmtime_r(x, y) gmtime_s(y, x)
#endif
#endif

static char* event_types[] = {
    EVENT_TYPE_GIT,
    EVENT_TYPE_WEB
};

#ifdef WIN32
STATIC DWORD WINAPI wm_github_main(void* arg);              // Module main function. It won't return
#else
STATIC void* wm_github_main(wm_github* github_config);    // Module main function. It won't return
#endif
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
 * @param subscription_name Event type to search
 * @return Pointer to organization node if exists, NULL otherwise
 */
STATIC wm_github_fail* wm_github_get_fail_by_org_and_type(wm_github_fail *fails, char *org_name, char* event_type);

/**
 * @brief Increase failure counter for organization node and send failure message to manager if necessary
 * @param current_fails Organizations failure list
 * @param org_name Organization name to search
 * @param subscription_name Event type to search
 * @param error_msg Error message to send
 * @param queue_fd Socket ID
 */
STATIC void wm_github_scan_failure_action(wm_github_fail **current_fails, char *org_name, char* event_type, char *error_msg, int queue_fd);

/* Context definition */
const wm_context WM_GITHUB_CONTEXT = {
    .name = GITHUB_WM_NAME,
    .start = (wm_routine)wm_github_main,
    .destroy = (void(*)(void *))wm_github_destroy,
    .dump = (cJSON * (*)(const void *))wm_github_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

#ifdef WIN32
DWORD WINAPI wm_github_main(void* arg) {
    wm_github* github_config = (wm_github *)arg;
#else
void * wm_github_main(wm_github* github_config) {
#endif
    if (github_config->enabled) {
        mtinfo(WM_GITHUB_LOGTAG, "Module GitHub started.");

#ifndef WIN32
        // Connect to queue
        github_config->queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
        if (github_config->queue_fd < 0) {
            mterror(WM_GITHUB_LOGTAG, "Can't connect to queue. Closing module.");
#ifdef WIN32
            return 0;
#else
            return NULL;
#endif
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

#ifdef WIN32
    return 0;
#else
    return NULL;
#endif
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
        os_free(current->event_type);
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
    unsigned int event_types_len = 0;
    unsigned int event_types_it = 0;
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
    char new_scan_time_str[80];
    char last_scan_time_str[80];
    struct tm tm_scan = { .tm_sec = 0 };

    while (current != NULL)
    {
        next = current->next;

        mtdebug1(WM_GITHUB_LOGTAG, "Scanning organization: '%s'", current->org_name);

        event_types_len = array_size(event_types);

        for (event_types_it = 0; event_types_it < event_types_len; ++event_types_it) {

            if (!strcmp(github_config->event_type, EVENT_TYPE_ALL) || !strcmp(event_types[event_types_it], github_config->event_type)) {
                scan_finished = 0;
                fail = 0;

                memset(org_state_name, '\0', OS_SIZE_1024);
                snprintf(org_state_name, OS_SIZE_1024 -1, "%s-%s-%s", WM_GITHUB_CONTEXT.name, current->org_name, event_types[event_types_it]);

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
                    } else if (isDebug()) {
                        memset(new_scan_time_str, '\0', 80);
                        gmtime_r(&new_scan_time, &tm_scan);
                        strftime(new_scan_time_str, sizeof(new_scan_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_scan);
                        mtdebug1(WM_GITHUB_LOGTAG, "Bookmark updated to '%s' for organization '%s' and event type '%s', waiting '%ld' seconds to run first scan.",
                            new_scan_time_str, current->org_name, event_types[event_types_it], github_config->interval);
                    }
                    continue;
                }

                last_scan_time = (time_t)org_state_struc.last_log_time + 1;

                memset(last_scan_time_str, '\0', 80);
                gmtime_r(&last_scan_time, &tm_scan);
                strftime(last_scan_time_str, sizeof(last_scan_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_scan);

                memset(new_scan_time_str, '\0', 80);
                gmtime_r(&new_scan_time, &tm_scan);
                strftime(new_scan_time_str, sizeof(new_scan_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_scan);

                memset(url, '\0', OS_SIZE_8192);
                snprintf(url, OS_SIZE_8192 -1, GITHUB_API_URL, current->org_name, last_scan_time_str, new_scan_time_str, event_types[event_types_it], ITEM_PER_PAGE);

                mtdebug1(WM_GITHUB_LOGTAG, "GitHub API URL: '%s'", url);

                char auth_header[OS_SIZE_8192];
                snprintf(auth_header, OS_SIZE_8192 -1, "Authorization: token %s", current->api_token);

                os_calloc(2, sizeof(char*), headers);
                headers[0] = auth_header;
                headers[1] = NULL;

                while (!scan_finished) {
                    response = wurl_http_request(WURL_GET_METHOD, headers, url, NULL, github_config->curl_max_size, WM_GITHUB_DEFAULT_CURL_REQUEST_TIMEOUT);

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
                                        snprintf(url, sizeof(url), "%s", next_page);
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
                    wm_github_scan_failure_action(&github_config->fails, current->org_name, event_types[event_types_it], error_msg, github_config->queue_fd);
                } else {
                    org_state_struc.last_log_time = new_scan_time;
                    if (wm_state_io(org_state_name, WM_IO_WRITE, &org_state_struc, sizeof(org_state_struc)) < 0) {
                        mterror(WM_GITHUB_LOGTAG, "Couldn't save running state.");
                    } else {
                        mtdebug1(WM_GITHUB_LOGTAG, "Bookmark updated to '%s' for organization '%s' and event type '%s', waiting '%ld' seconds to run next scan.",
                            new_scan_time_str, current->org_name, event_types[event_types_it], github_config->interval);
                    }

                    if (org_fail = wm_github_get_fail_by_org_and_type(github_config->fails,
                        current->org_name, event_types[event_types_it]), org_fail && org_fail->fails) {
                        mtinfo(WM_GITHUB_LOGTAG, "Github organization '%s' and event type '%s', connected successfully.",
                            current->org_name, event_types[event_types_it]);
                        org_fail->fails = 0;
                    }
                }

                os_free(error_msg);
                os_free(headers);
            }
        }

        current = next;
    }
}

STATIC wm_github_fail* wm_github_get_fail_by_org_and_type(wm_github_fail *fails, char *org_name, char* event_type) {
    wm_github_fail* current;
    current = fails;
    int target_org = 0;

    while (!target_org)
    {
        if (current == NULL) {
            target_org = 1;
            continue;
        }

        if (!strncmp(current->org_name, org_name, strlen(org_name)) && (!current->event_type ||
            (event_type && current->event_type && !strncmp(current->event_type, event_type, strlen(event_type))))) {
            target_org = 1;
        } else {
            current = current->next;
        }

    }

    return current;
}

STATIC void wm_github_scan_failure_action(wm_github_fail **current_fails, char *org_name, char* event_type, char *error_msg, int queue_fd) {
    char *payload;
    wm_github_fail *org_fail;

    org_fail = wm_github_get_fail_by_org_and_type(*current_fails, org_name, event_type);

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
        if (event_type) {
            os_strdup(event_type, org_fail->event_type);
        }

        org_fail->fails = 1;
    } else {
        org_fail->fails++;

        if (org_fail->fails == RETRIES_TO_SEND_ERROR) {
            // Send fail message
            cJSON *msg_obj = cJSON_Parse(error_msg);
            cJSON *fail_object = cJSON_CreateObject();
            cJSON *fail_github = cJSON_CreateObject();

            cJSON_AddStringToObject(fail_object, "actor", "wazuh");
            cJSON_AddStringToObject(fail_object, "organization", org_name);
            if (event_type) {
                cJSON_AddStringToObject(fail_object, "event_type", event_type);
            }

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

            mtwarn(WM_GITHUB_LOGTAG, "Sending GitHub internal message: '%s'", payload);

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
