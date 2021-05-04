/*
 * Wazuh Module for GitHub logs
 * Copyright (C) 2015-2021, Wazuh Inc.
 * July 3, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

static void* wm_github_main(wm_github* github_config);    // Module main function. It won't return
static void wm_github_destroy(wm_github* github_config);
static void wm_github_auth_destroy(wm_github_auth* github_auth);
static void wm_github_fail_destroy(wm_github_fail* github_fails);
static wm_github_fail* wm_github_get_fail_by_org(wm_github_fail *fails, char *org_name);
static int wm_github_execute_scan(wm_github *github_config, int initial_scan);
static curl_response* wm_github_execute_curl(char *token, const char *url);
static char* wm_github_get_next_page(char *header);
static void wm_github_scan_failure_action(wm_github_fail **current_fails, char *org_name, char *error_msg, int queue_fd, char *last_scan_time_str, char *url);
cJSON *wm_github_dump(const wm_github* github_config);

/* Context definition */
const wm_context WM_GITHUB_CONTEXT = {
    GITHUB_WM_NAME,
    (wm_routine)wm_github_main,
    (wm_routine)(void *)wm_github_destroy,
    (cJSON * (*)(const void *))wm_github_dump,
    NULL
};

void * wm_github_main(wm_github* github_config) {

    if (github_config->enabled) {
        mtinfo(WM_GITHUB_LOGTAG, "Module GitHub started.");

#ifndef WIN32
        // Connect to queue
        github_config->queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);
        if (github_config->queue_fd < 0) {
            mterror(WM_OSQUERYMONITOR_LOGTAG, "Can't connect to queue. Closing module.");
            return NULL;
        }
#endif

        if (github_config->run_on_start) {
            // Execute initial scan
            wm_github_execute_scan(github_config, 1);
        }

        while (1) {
            sleep(github_config->interval);
            wm_github_execute_scan(github_config, 0);
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

void wm_github_free_response(curl_response* response)
{
    os_free(response->header);
    os_free(response->body);
    os_free(response);
}

cJSON *wm_github_dump(const wm_github* github_config) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_info = cJSON_CreateObject();

    if (github_config->enabled) {
        cJSON_AddStringToObject(wm_info, "enabled", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "enabled", "no");
    }
    if (github_config->run_on_start) {
        cJSON_AddStringToObject(wm_info, "run_on_start", "yes");
    } else {
        cJSON_AddStringToObject(wm_info, "run_on_start", "no");
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

size_t wm_github_write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t realsize = size * nmemb;
    curl_request *req = (curl_request *) userdata;

    while (req->buflen < req->len + realsize + 1)
    {
        os_realloc(req->buffer, req->buflen + CHUNK_SIZE, req->buffer);
        req->buflen += CHUNK_SIZE;
    }
    memcpy(&req->buffer[req->len], ptr, realsize);
    req->len += realsize;
    req->buffer[req->len] = '\0';

    return realsize;
}

static int wm_github_execute_scan(wm_github *github_config, int initial_scan) {
    wm_github_auth* current = github_config->auth;
    wm_github_auth* next = NULL;
    curl_response *response;
    wm_github_fail *org_fail;
    wm_github_state org_state_struc;
    int scan_finished = 0;
    int fail = 0;
    char *next_page = NULL;
    char *payload;
    char url[OS_SIZE_8192];
    char org_state_name[OS_SIZE_1024];
    char last_scan_time_str[OS_SIZE_1024];
    time_t last_scan_time;
    time_t new_scan_time;
    char *error_msg = NULL;

    while (current != NULL)
    {
        next = current->next;
        scan_finished = 0;
        fail = 0;
        mtdebug1(WM_GITHUB_LOGTAG, "Scanning organization: '%s'", current->org_name);

        memset(org_state_name, '\0', OS_SIZE_1024);
        snprintf(org_state_name, OS_SIZE_1024 -1, "%s-%s", WM_GITHUB_CONTEXT.name, current->org_name);

        // Load state for organization
        if (wm_state_io(org_state_name, WM_IO_READ, &org_state_struc, sizeof(org_state_struc)) < 0) {
            memset(&org_state_struc, 0, sizeof(org_state_struc));
            org_state_struc.last_log_time = 0;
            memset(org_state_struc.next_page, '\0', OS_SIZE_8192);
        }

        last_scan_time = (time_t)org_state_struc.last_log_time + 1;
        new_scan_time = time(0) - github_config->time_delay;

        memset(last_scan_time_str, '\0', OS_SIZE_1024);
        strftime(last_scan_time_str, 20, "%Y-%m-%dT%H:%M:%SZ", localtime(&last_scan_time));

        if (initial_scan && github_config->only_future_events) {
            org_state_struc.last_log_time = new_scan_time;
            if (wm_state_io(org_state_name, WM_IO_WRITE, &org_state_struc, sizeof(org_state_struc)) < 0) {
                mterror(WM_GITHUB_LOGTAG, "Couldn't save running state.");
            }
            scan_finished = 1;
            fail = 0;
        }

        memset(url, '\0', OS_SIZE_8192);
        if (org_state_struc.next_page[0] == '\0') {
            snprintf(url, OS_SIZE_8192 -1, GITHUB_API_URL, current->org_name, last_scan_time_str, github_config->event_type, ITEM_PER_PAGE);
        } else {
            strncpy(url, org_state_struc.next_page, strlen(org_state_struc.next_page));
        }

        mtdebug1(WM_GITHUB_LOGTAG, "GitHub API URL: '%s'", url);

        while (!scan_finished) {
            response = wm_github_execute_curl(current->api_token, url);

            if (response) {
                if (response->status_code == 200) {
                    // Load body to json and sent as localfile
                    cJSON *array_logs_json = NULL;

                    if (array_logs_json = cJSON_Parse(response->body), !array_logs_json) {
                        mtdebug1(WM_GITHUB_LOGTAG,"Error parsing response body.");
                        scan_finished = 1;
                        fail = 1;
                    } else {
                        int response_lenght = cJSON_GetArraySize(array_logs_json);

                        for (int i = 0 ; i < response_lenght ; i++) {
                            cJSON * subitem = cJSON_GetArrayItem(array_logs_json, i);

                            if (subitem) {
                                cJSON_AddStringToObject(subitem, "source", WM_GITHUB_CONTEXT.name);
                                payload = cJSON_PrintUnformatted(subitem);
                                mtdebug2(WM_GITHUB_LOGTAG, "Sending GitHub log: '%s'", payload);

                                if (wm_sendmsg(WM_GITHUB_MSG_DELAY, github_config->queue_fd, payload, WM_GITHUB_CONTEXT.name, LOCALFILE_MQ) < 0) {
                                    mterror(WM_GITHUB_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                                }
                                os_free(payload);
                            }
                        }

                        if (response_lenght == ITEM_PER_PAGE) {
                            next_page = wm_github_get_next_page(response->header);
                            if (next_page == NULL) {
                                scan_finished = 1;
                            } else {
                                memset(url, '\0', OS_SIZE_8192);
                                strncpy(url, next_page, strlen(next_page));
                                os_free(next_page);
                            }
                        } else {
                            scan_finished = 1;
                        }

                        cJSON_Delete(array_logs_json);
                    }
                } else {
                    if (response->body) {
                        os_malloc(strlen(response->body) + 1, error_msg);
                        strncpy(error_msg, response->body, strlen(response->body));
                    }
                    scan_finished = 1;
                    fail = 1;
                }

                wm_github_free_response(response);
            } else {
                scan_finished = 1;
                fail = 1;
            }
        }

        if (fail) {
            wm_github_scan_failure_action(&github_config->fails, current->org_name, error_msg, github_config->queue_fd, last_scan_time_str, url);

            memset(org_state_struc.next_page, '\0', OS_SIZE_8192);
            strncpy(org_state_struc.next_page, url, strlen(url));
            if (wm_state_io(org_state_name, WM_IO_WRITE, &org_state_struc, sizeof(org_state_struc)) < 0) {
                mterror(WM_GITHUB_LOGTAG, "Couldn't save running state.");
            }
        } else {
            org_state_struc.last_log_time = new_scan_time;
            memset(org_state_struc.next_page, '\0', OS_SIZE_8192);
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
    }

    return 0;
}

static wm_github_fail* wm_github_get_fail_by_org(wm_github_fail *fails, char *org_name) {
    wm_github_fail* current;
    current = fails;
    int target_org = 0;

    while (!target_org)
    {
        if (current == NULL) {
            mtdebug1(WM_GITHUB_LOGTAG, "No record for this organization: '%s'", org_name);
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

static curl_response* wm_github_execute_curl(char *token, const char* url) {
    char auth_header[PATH_MAX];
    curl_response *response;
    struct curl_slist* headers = NULL;
    CURLcode res;
    curl_request req = {.buffer = NULL, .len = 0, .buflen = 0};
    curl_request req_header = {.buffer = NULL, .len = 0, .buflen = 0};

    CURL* curl = curl_easy_init();

    if (!curl) {
        mtdebug1(WM_GITHUB_LOGTAG, "curl initialization failure");
        return NULL;
    }

    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "GET");
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    curl_easy_setopt(curl, CURLOPT_DEFAULT_PROTOCOL, "https");

    headers = curl_slist_append(headers, "User-Agent: curl/7.58.0");

    memset(auth_header, '\0', PATH_MAX);
    snprintf(auth_header, PATH_MAX -1, "Authorization: token %s", token);
    headers = curl_slist_append(headers, auth_header);

    os_malloc(CHUNK_SIZE, req.buffer);
    req.buflen = CHUNK_SIZE;

    os_malloc(CHUNK_SIZE, req_header.buffer);
    req_header.buflen = CHUNK_SIZE;

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, wm_github_write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&req);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, wm_github_write_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, (void *)&req_header);
    curl_easy_setopt(curl, CURLOPT_URL, url);

    res = curl_easy_perform(curl);

    if (res != CURLE_OK) {
        mtdebug1(WM_GITHUB_LOGTAG,"curl_easy_perform() failed: %s", curl_easy_strerror(res));
    }

    os_calloc(1, sizeof(curl_response), response);
    curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE, &response->status_code);
    response->header = req_header.buffer;
    response->body = req.buffer;

    curl_easy_cleanup(curl);

    return response;
}

static char* wm_github_get_next_page(char *header) {
    char *next_page = NULL;
    OSRegex regex;

    if (!OSRegex_Compile("<(\\S+)>;\\s*rel=\"next\"", &regex, OS_RETURN_SUBSTRING)) {
        mtwarn(WM_GITHUB_LOGTAG, "Cannot compile regex");
        return NULL;
    }

    if (!OSRegex_Execute(header, &regex)) {
        mtdebug1(WM_GITHUB_LOGTAG, "No match regex.");
        OSRegex_FreePattern(&regex);
        return NULL;
    }

    if (!regex.d_sub_strings[0]) {
        mtdebug1(WM_GITHUB_LOGTAG, "No next page was captured.");
        OSRegex_FreePattern(&regex);
        return NULL;
    }

    os_strdup(regex.d_sub_strings[0], next_page);

    OSRegex_FreePattern(&regex);
    return next_page;
}

static void wm_github_scan_failure_action(wm_github_fail **current_fails, char *org_name, char *error_msg, int queue_fd, char *last_scan_time_str, char *url) {
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

        os_malloc(strlen(org_name) + 1, org_fail->org_name);
        strncpy(org_fail->org_name, org_name, strlen(org_name));

        org_fail->fails = 1;
    } else {
        org_fail->fails = org_fail->fails + 1;

        if (org_fail->fails == RETRIES_TO_SEND_ERROR) {
            // Send fail message
            cJSON *msg_obj = cJSON_Parse(error_msg);
            cJSON *fail_object = cJSON_CreateObject();
            cJSON_AddStringToObject(fail_object, "actor", "wazuh");
            cJSON_AddStringToObject(fail_object, "source", WM_GITHUB_CONTEXT.name);
            cJSON_AddStringToObject(fail_object, "created_at", last_scan_time_str);
            cJSON_AddStringToObject(fail_object, "request", url);

            if (msg_obj) {
                payload = cJSON_PrintUnformatted(msg_obj);
                cJSON_AddStringToObject(fail_object, "response", payload);
                os_free(payload);
            } else {
                cJSON_AddStringToObject(fail_object, "response", "Unknown error");
            }

            payload = cJSON_PrintUnformatted(fail_object);
            mtdebug2(WM_GITHUB_LOGTAG, "Sending GitHub internal message: '%s'", payload);

            if (wm_sendmsg(WM_GITHUB_MSG_DELAY, queue_fd, payload, WM_GITHUB_CONTEXT.name, LOCALFILE_MQ) < 0) {
                mterror(WM_GITHUB_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
            }

            os_free(payload);
            cJSON_Delete(fail_object);
            cJSON_Delete(msg_obj);
        }
    }
}
