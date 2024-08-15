/*
 * Wazuh Module for Microsoft Graph integration
 * Copyright (C) 2023, InfoDefense Inc.
 * March, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#if defined(WIN32) || defined(__linux__) || defined(__MACH__)

#include "wmodules.h"
#include "wm_ms_graph.h"

#ifdef WIN32
#ifdef WAZUH_UNIT_TESTING
#define gmtime_r(x, y)
#else
#define gmtime_r(x, y) gmtime_s(y, x)
#endif
#endif

static void* wm_ms_graph_main(wm_ms_graph* ms_graph);
static bool wm_ms_graph_setup(wm_ms_graph* ms_graph);
static bool wm_ms_graph_check();
static void wm_ms_graph_get_access_token(wm_ms_graph_auth* auth_config, const ssize_t curl_max_size);
static void wm_ms_graph_scan_relationships(wm_ms_graph* ms_graph, wm_ms_graph_auth* auth_config, const bool initial_scan);
static cJSON* wm_ms_graph_scan_apps_devices(const wm_ms_graph* ms_graph, const cJSON* app_id, const char* query_fqdn, char** headers);
static void wm_ms_graph_destroy(wm_ms_graph* ms_graph);
static void wm_ms_graph_cleanup();
cJSON* wm_ms_graph_dump(const wm_ms_graph* ms_graph);

static int queue_fd; // Socket ID

const wm_context WM_MS_GRAPH_CONTEXT = {
    .name = MS_GRAPH_WM_NAME,
    .start = (wm_routine)wm_ms_graph_main,
    .destroy = (void (*)(void*))wm_ms_graph_destroy,
    .dump = (cJSON* (*)(const void*))wm_ms_graph_dump,
    .sync = NULL,
    .stop = NULL,
    .query = NULL,
};

void* wm_ms_graph_main(wm_ms_graph* ms_graph) {
    char* timestamp = NULL;

    if (!wm_ms_graph_setup(ms_graph)) {
        return NULL;
    } else {
        mtinfo(WM_MS_GRAPH_LOGTAG, "Started module.");

        bool initial = true;
        int i;
        wm_ms_graph_auth *it;

        while (FOREVER()) {
            const time_t time_sleep = sched_scan_get_time_until_next_scan(&ms_graph->scan_config, WM_MS_GRAPH_LOGTAG, ms_graph->run_on_start);

            if (ms_graph->state.next_time == 0) {
                ms_graph->state.next_time = ms_graph->scan_config.time_start + time_sleep;
            }

            if (time_sleep) {
                const time_t next_scan_time = sched_get_next_scan_time(ms_graph->scan_config);
                timestamp = w_get_timestamp(next_scan_time);
                mtdebug1(WM_MS_GRAPH_LOGTAG, "Waiting until: %s", timestamp);
                os_free(timestamp);
                w_sleep_until(next_scan_time);
            }

            for (i = 0; ms_graph->auth_config[i]; i++) {
                it = ms_graph->auth_config[i];

                if (!it->access_token || time(NULL) >= it->token_expiration_time) {
                    mtinfo(WM_MS_GRAPH_LOGTAG, "Obtaining access token.");
                    wm_ms_graph_get_access_token(it, ms_graph->curl_max_size);
                }

                if (it->access_token && time(NULL) < it->token_expiration_time) {
                    mtinfo(WM_MS_GRAPH_LOGTAG, "Scanning tenant '%s'", it->tenant_id);
                    wm_ms_graph_scan_relationships(ms_graph, it, initial);
                    initial = false;
                }
            }
        }
    }
    return NULL;
}

bool wm_ms_graph_setup(wm_ms_graph* ms_graph) {

    if (!wm_ms_graph_check(ms_graph)) {
        return false;
    }

    if (wm_state_io(WM_MS_GRAPH_CONTEXT.name, WM_IO_READ, &ms_graph->state, sizeof(ms_graph->state)) < 0) {
        memset(&ms_graph->state, 0, sizeof(ms_graph->state));
    }

    queue_fd = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (queue_fd < 0) {
        mterror(WM_MS_GRAPH_LOGTAG, "Unable to connect to Message Queue. Exiting...");
        #ifdef WAZUH_UNIT_TESTING
        return false;
        #else
        pthread_exit(NULL);
        #endif
    }

    atexit(wm_ms_graph_cleanup);
    return true;

}

bool wm_ms_graph_check(wm_ms_graph* ms_graph) {

    if (!ms_graph || !ms_graph->enabled) {
        mtinfo(WM_MS_GRAPH_LOGTAG, "Module disabled. Exiting...");
        #ifdef WAZUH_UNIT_TESTING
        return false;
        #else
        pthread_exit(NULL);
        #endif
    } else if (!ms_graph->resources || ms_graph->num_resources == 0) {
        mterror(WM_MS_GRAPH_LOGTAG, "Invalid module configuration (Missing API info, resources, relationships). Exiting...");
        #ifdef WAZUH_UNIT_TESTING
        return false;
        #else
        pthread_exit(NULL);
        #endif
    } else {
        for (unsigned int resource = 0; resource < ms_graph->num_resources; resource++) {
            if (ms_graph->resources[resource].num_relationships == 0) {
                mterror(WM_MS_GRAPH_LOGTAG, "Invalid module configuration (Missing API info, resources, relationships). Exiting...");
                #ifdef WAZUH_UNIT_TESTING
                return false;
                #else
                pthread_exit(NULL);
                #endif
            }
        }
    }
    return true;
}

void wm_ms_graph_get_access_token(wm_ms_graph_auth* auth_config, const ssize_t curl_max_size) {
    char url[OS_SIZE_8192] = { '\0' };
    char payload[OS_SIZE_8192] = { '\0' };
    char* headers[] = { "Content-Type: application/x-www-form-urlencoded", NULL };
    curl_response* response;

    snprintf(url, OS_SIZE_8192 - 1, WM_MS_GRAPH_ACCESS_TOKEN_URL, auth_config->login_fqdn, auth_config->tenant_id);
    mtdebug1(WM_MS_GRAPH_LOGTAG, "Microsoft Graph API Access Token URL: '%s'", url);
    snprintf(payload, OS_SIZE_8192 - 1, WM_MS_GRAPH_ACCESS_TOKEN_PAYLOAD, auth_config->query_fqdn, auth_config->client_id, auth_config->secret_value);

    response = wurl_http_request(WURL_POST_METHOD, headers, url, payload, curl_max_size, WM_MS_GRAPH_DEFAULT_TIMEOUT);
    if (response) {
        if (response->status_code != 200) {
            char status_code[4];
            snprintf(status_code, 4, "%ld", response->status_code);
            mtwarn(WM_MS_GRAPH_LOGTAG, "Received unsuccessful status code when attempting to obtain access token: Status code was '%s' & response was '%s'", status_code, response->body);
        } else if (response->max_size_reached) {
            mtwarn(WM_MS_GRAPH_LOGTAG, "Reached maximum CURL size when attempting to obtain access token. Consider increasing the value of 'curl_max_size'.");
        } else {
            cJSON* response_body = NULL;
            if (response_body = cJSON_Parse(response->body), response_body) {
                cJSON* access_token_value = cJSON_GetObjectItem(response_body, "access_token");
                cJSON* access_token_expiration = cJSON_GetObjectItem(response_body, "expires_in");
                if (cJSON_IsString(access_token_value) && cJSON_IsNumber(access_token_expiration)) {
                    os_strdup(access_token_value->valuestring, auth_config->access_token);
                    auth_config->token_expiration_time = time(NULL) + access_token_expiration->valueint;
                } else {
                    mtwarn(WM_MS_GRAPH_LOGTAG, "Incomplete access token response, value or expiration time not present.");
                }
                cJSON_Delete(response_body);
            } else {
                mtwarn(WM_MS_GRAPH_LOGTAG, "Failed to parse access token JSON body.");
            }
        }
        wurl_free_response(response);
    } else {
        mtwarn(WM_MS_GRAPH_LOGTAG, "No response received when attempting to obtain access token.");
    }
}

void wm_ms_graph_scan_relationships(wm_ms_graph* ms_graph, wm_ms_graph_auth* auth_config, const bool initial_scan) {
    char url[OS_SIZE_8192] = { '\0' };
    char auth_header[OS_SIZE_8192] = { '\0' };
    char* headers[] = { NULL, NULL };
    curl_response* response;
    char relationship_state_name[OS_SIZE_1024] = { '\0' };
    char start_time_str[WM_MS_GRAPH_TIMESTAMP_SIZE_80] = { '\0' };
    char end_time_str[WM_MS_GRAPH_TIMESTAMP_SIZE_80] = { '\0' };
    struct tm tm_aux = { .tm_sec = 0 };
    wm_ms_graph_state_t relationship_state_struc;
    time_t now;
    bool fail;
    bool next_page;
    bool inventory = false;

#ifndef WIN32
    int id = os_random();
    if (id < 0) {
        id = -id;
    }
#else
    char random_id[RANDOM_LENGTH];
    snprintf(random_id, RANDOM_LENGTH - 1, "%u%u", os_random(), os_random());
    int id = atoi(random_id);

    if (id < 0) {
        id = -id;
    }
#endif

    for (unsigned int resource_num = 0; resource_num < ms_graph->num_resources; resource_num++) {

        for (unsigned int relationship_num = 0; relationship_num < ms_graph->resources[resource_num].num_relationships; relationship_num++) {

            if (!strcmp(ms_graph->resources[resource_num].name, WM_MS_GRAPH_RESOURCE_DEVICE_MANAGEMENT)) {
                // If not auditEvents, treat as inventory
                if (strcmp(ms_graph->resources[resource_num].relationships[relationship_num], WM_MS_GRAPH_RELATIONSHIP_AUDIT_EVENTS)) {
                    inventory = true;
                }
            }

            if (!inventory) {
                snprintf(relationship_state_name, OS_SIZE_1024 -1, "%s-%s-%s-%s", WM_MS_GRAPH_CONTEXT.name,
                    auth_config->tenant_id, ms_graph->resources[resource_num].name, ms_graph->resources[resource_num].relationships[relationship_num]);

                memset(&relationship_state_struc, 0, sizeof(relationship_state_struc));

                // Load state for tenant-resource-relationship
                if (wm_state_io(relationship_state_name, WM_IO_READ, &relationship_state_struc, sizeof(relationship_state_struc)) < 0) {
                    memset(&relationship_state_struc, 0, sizeof(relationship_state_struc));
                }

                now = time(0);

                if ((initial_scan && (!relationship_state_struc.next_time || ms_graph->only_future_events)) ||
                    (!initial_scan && !relationship_state_struc.next_time)) {
                    relationship_state_struc.next_time = now;
                    if (wm_state_io(relationship_state_name, WM_IO_WRITE, &relationship_state_struc, sizeof(relationship_state_struc)) < 0) {
                        mterror(WM_MS_GRAPH_LOGTAG, "Couldn't save running state.");
                    } else if (isDebug()) {
                        gmtime_r(&now, &tm_aux);
                        strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_aux);
                        mtdebug1(WM_MS_GRAPH_LOGTAG, "Bookmark updated to '%s' for tenant '%s' resource '%s' and relationship '%s', waiting '%d' seconds to run first scan.",
                            start_time_str, auth_config->tenant_id, ms_graph->resources[resource_num].name, ms_graph->resources[resource_num].relationships[relationship_num], ms_graph->scan_config.interval);
                    }
                    continue;
                }

                gmtime_r(&relationship_state_struc.next_time, &tm_aux);
                strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_aux);

                gmtime_r(&now, &tm_aux);
                strftime(end_time_str, sizeof(end_time_str), "%Y-%m-%dT%H:%M:%SZ", &tm_aux);
            }

            snprintf(auth_header, OS_SIZE_8192 - 1, "Authorization: Bearer %s", auth_config->access_token);
            os_strdup(auth_header, headers[0]);

            if (!strcmp(ms_graph->resources[resource_num].name, WM_MS_GRAPH_RESOURCE_DEVICE_MANAGEMENT)) {
                if (!strcmp(ms_graph->resources[resource_num].relationships[relationship_num], WM_MS_GRAPH_RELATIONSHIP_AUDIT_EVENTS)) {
                    snprintf(url, OS_SIZE_8192 - 1, WM_MS_GRAPH_API_URL_FILTER_ACTIVITY_DATE,
                    auth_config->query_fqdn,
                    ms_graph->version,
                    WM_MS_GRAPH_RESOURCE_DEVICE_MANAGEMENT,
                    WM_MS_GRAPH_RELATIONSHIP_AUDIT_EVENTS,
                    WM_MS_GRAPH_ITEM_PER_PAGE,
                    start_time_str,
                    end_time_str);
                } else {
                    snprintf(url, OS_SIZE_8192 - 1, WM_MS_GRAPH_API_URL,
                    auth_config->query_fqdn,
                    ms_graph->version,
                    WM_MS_GRAPH_RESOURCE_DEVICE_MANAGEMENT,
                    ms_graph->resources[resource_num].relationships[relationship_num],
                    WM_MS_GRAPH_ITEM_PER_PAGE);
                }
            } else {
                snprintf(url, OS_SIZE_8192 - 1, WM_MS_GRAPH_API_URL_FILTER_CREATED_DATE,
                auth_config->query_fqdn,
                ms_graph->version,
                ms_graph->resources[resource_num].name,
                ms_graph->resources[resource_num].relationships[relationship_num],
                WM_MS_GRAPH_ITEM_PER_PAGE,
                start_time_str,
                end_time_str);
            }

            next_page = true;
            while (next_page) {
                mtdebug1(WM_MS_GRAPH_LOGTAG, "Microsoft Graph API Log URL: '%s'", url);

                fail = true;
                next_page = false;
                response = wurl_http_request(WURL_GET_METHOD, headers, url, "", ms_graph->curl_max_size, WM_MS_GRAPH_DEFAULT_TIMEOUT);
                if (response) {
                    if (response->status_code != 200) {
                        char status_code[4];
                        snprintf(status_code, 4, "%ld", response->status_code);
                        mtwarn(WM_MS_GRAPH_LOGTAG, "Received unsuccessful status code when attempting to get relationship '%s' logs: Status code was '%s' & response was '%s'",
                        ms_graph->resources[resource_num].relationships[relationship_num],
                        status_code,
                        response->body);
                        if (response->status_code == 401) {
                            auth_config->token_expiration_time = time(NULL);
                        }
                    } else if (response->max_size_reached) {
                        mtwarn(WM_MS_GRAPH_LOGTAG, "Reached maximum CURL size when attempting to get relationship '%s' logs. Consider increasing the value of 'curl_max_size'.",
                        ms_graph->resources[resource_num].relationships[relationship_num]);
                    } else {
                        cJSON* body_parse = NULL;
                        if (body_parse = cJSON_Parse(response->body), body_parse) {
                            cJSON* logs = cJSON_GetObjectItem(body_parse, "value");
                            int num_logs = cJSON_GetArraySize(logs);
                            if (num_logs > 0) {
                                for (int log_index = 0; log_index < num_logs; log_index++) {
                                    cJSON* log = NULL;
                                    if (log = cJSON_GetArrayItem(logs, log_index), log) {
                                        cJSON* full_log = cJSON_CreateObject();
                                        char* payload;

                                        if (inventory && !strcmp(ms_graph->resources[resource_num].relationships[relationship_num], WM_MS_GRAPH_RELATIONSHIP_DETECTED_APPS)) {
                                            cJSON_AddItemToObject(log, WM_MS_GRAPH_RELATIONSHIP_MANAGED_DEVICES,
                                                wm_ms_graph_scan_apps_devices(ms_graph, cJSON_GetObjectItem(log, "id"), auth_config->query_fqdn, headers));
                                        }

                                        cJSON_AddStringToObject(log, "resource", ms_graph->resources[resource_num].name);
                                        cJSON_AddStringToObject(log, "relationship", ms_graph->resources[resource_num].relationships[relationship_num]);

                                        if (inventory) {
                                            cJSON_AddNumberToObject(full_log, "scan_id", id);
                                        }
                                        cJSON_AddStringToObject(full_log, "integration", WM_MS_GRAPH_CONTEXT.name);
                                        cJSON_AddItemToObject(full_log, WM_MS_GRAPH_CONTEXT.name, cJSON_Duplicate(log, true));

                                        payload = cJSON_PrintUnformatted(full_log);
                                        mtdebug2(WM_MS_GRAPH_LOGTAG, "Sending log: '%s'", payload);
                                        if (wm_sendmsg(1000000 / wm_max_eps, queue_fd, payload, WM_MS_GRAPH_CONTEXT.name, LOCALFILE_MQ) < 0) {
                                            mterror(WM_MS_GRAPH_LOGTAG, QUEUE_ERROR, DEFAULTQUEUE, strerror(errno));
                                        }

                                        os_free(payload);
                                        cJSON_Delete(full_log);
                                    } else {
                                        mtwarn(WM_MS_GRAPH_LOGTAG, "Failed to parse log array into singular log.");
                                    }
                                }
                                fail = false;
                            } else {
                                mtdebug2(WM_MS_GRAPH_LOGTAG, "No new logs received.");
                                fail = false;
                            }

                            cJSON* next_url = cJSON_GetObjectItem(body_parse, "@odata.nextLink");
                            if (cJSON_IsString(next_url)) {
                                memset(url, '\0', OS_SIZE_8192);
                                snprintf(url, OS_SIZE_8192 -1, "%s", next_url->valuestring);
                                next_page = true;
                            }

                            cJSON_Delete(body_parse);
                        } else {
                            mtwarn(WM_MS_GRAPH_LOGTAG, "Failed to parse relationship '%s' JSON body.", ms_graph->resources[resource_num].relationships[relationship_num]);
                        }
                    }
                    wurl_free_response(response);
                } else {
                    mtwarn(WM_MS_GRAPH_LOGTAG, "No response received when attempting to get relationship '%s' from resource '%s' on API version '%s'.",
                    ms_graph->resources[resource_num].relationships[relationship_num],
                    ms_graph->resources[resource_num].name,
                    ms_graph->version);
                }
            }

            if (!inventory && !fail) {
                relationship_state_struc.next_time = now;
                if (wm_state_io(relationship_state_name, WM_IO_WRITE, &relationship_state_struc, sizeof(relationship_state_struc)) < 0) {
                    mterror(WM_MS_GRAPH_LOGTAG, "Couldn't save running state.");
                } else {
                    mtdebug1(WM_MS_GRAPH_LOGTAG, "Bookmark updated to '%s' for tenant '%s' resource '%s' and relationship '%s', waiting '%d' seconds to run next scan.",
                        end_time_str, auth_config->tenant_id, ms_graph->resources[resource_num].name, ms_graph->resources[resource_num].relationships[relationship_num], ms_graph->scan_config.interval);
                }
            }
            os_free(headers[0]);
        }
    }
}

cJSON* wm_ms_graph_scan_apps_devices(const wm_ms_graph* ms_graph, const cJSON* app_id, const char* query_fqdn, char** headers) {
    char url[OS_SIZE_8192] = { '\0' };
    curl_response* response;
    bool next_page;

    cJSON *array = cJSON_CreateArray();

    if (cJSON_IsString(app_id)) {
        snprintf(url, OS_SIZE_8192 - 1, WM_MS_GRAPH_API_URL_FILTER_DEVICE_FIELDS, query_fqdn, ms_graph->version, WM_MS_GRAPH_RESOURCE_DEVICE_MANAGEMENT,
            WM_MS_GRAPH_RELATIONSHIP_DETECTED_APPS, app_id->valuestring, WM_MS_GRAPH_RELATIONSHIP_MANAGED_DEVICES, WM_MS_GRAPH_ITEM_PER_PAGE);

        next_page = true;
        while (next_page) {
            mtdebug1(WM_MS_GRAPH_LOGTAG, "Microsoft Graph API Log URL: '%s'", url);

            next_page = false;
            response = wurl_http_request(WURL_GET_METHOD, headers, url, "", ms_graph->curl_max_size, WM_MS_GRAPH_DEFAULT_TIMEOUT);
            if (response) {
                if (response->status_code == 200 && !response->max_size_reached) {
                    cJSON* body_parse = NULL;
                    if (body_parse = cJSON_Parse(response->body), body_parse) {
                        cJSON* logs = cJSON_GetObjectItem(body_parse, "value");
                        int num_logs = cJSON_GetArraySize(logs);
                        if (num_logs > 0) {
                            for (int log_index = 0; log_index < num_logs; log_index++) {
                                cJSON* log = NULL;
                                if (log = cJSON_GetArrayItem(logs, log_index), log) {
                                    cJSON_AddItemToArray(array, cJSON_Duplicate(log, true));
                                }
                            }
                        }

                        cJSON* next_url = cJSON_GetObjectItem(body_parse, "@odata.nextLink");
                        if (cJSON_IsString(next_url)) {
                            memset(url, '\0', OS_SIZE_8192);
                            snprintf(url, OS_SIZE_8192 -1, "%s", next_url->valuestring);
                            next_page = true;
                        }

                        cJSON_Delete(body_parse);
                    }
                }
                wurl_free_response(response);
            }
        }
    }

    return array;
}

void wm_ms_graph_destroy(wm_ms_graph* ms_graph) {

    for (unsigned int resource = 0; resource < ms_graph->num_resources; resource++) {
        for (unsigned int relationship = 0; relationship < ms_graph->resources[resource].num_relationships; relationship++) {
            os_free(ms_graph->resources[resource].relationships[relationship]);
        }
        os_free(ms_graph->resources[resource].name);
        os_free(ms_graph->resources[resource].relationships);
    }
    os_free(ms_graph->resources);

    int e;
    wm_ms_graph_auth *it;

    for (e = 0; ms_graph->auth_config && ms_graph->auth_config[e]; e++) {
        it = ms_graph->auth_config[e];
        os_free(it->tenant_id);
        os_free(it->client_id);
        os_free(it->secret_value);
        os_free(it->login_fqdn);
        os_free(it->query_fqdn);
        os_free(it->access_token);

        os_free(it);
    }

    os_free(ms_graph->auth_config);

    os_free(ms_graph->version);

    os_free(ms_graph);
}

void wm_ms_graph_cleanup() {
    close(queue_fd);
    mtinfo(WM_MS_GRAPH_LOGTAG, "Module shutdown.");
}

cJSON* wm_ms_graph_dump(const wm_ms_graph* ms_graph) {
    cJSON* root = cJSON_CreateObject();
    cJSON* ms_graph_info = cJSON_CreateObject();
    cJSON* ms_graph_auth = cJSON_CreateObject();

    if (ms_graph->enabled) {
        cJSON_AddStringToObject(ms_graph_info, "enabled", "yes");
    } else {
        cJSON_AddStringToObject(ms_graph_info, "enabled", "no");
    }
    if (ms_graph->only_future_events) {
        cJSON_AddStringToObject(ms_graph_info, "only_future_events", "yes");
    } else {
        cJSON_AddStringToObject(ms_graph_info, "only_future_events", "no");
    }
    if (ms_graph->curl_max_size) {
        cJSON_AddNumberToObject(ms_graph_info, "curl_max_size", ms_graph->curl_max_size);
    }
    if (ms_graph->run_on_start) {
        cJSON_AddStringToObject(ms_graph_info, "run_on_start", "yes");
    } else {
        cJSON_AddStringToObject(ms_graph_info, "run_on_start", "no");
    }
    if (ms_graph->version) {
        cJSON_AddStringToObject(ms_graph_info, "version", ms_graph->version);
    }
    sched_scan_dump(&ms_graph->scan_config, ms_graph_info);

    int e;
    wm_ms_graph_auth *it;

    for (e = 0; ms_graph->auth_config[e]; e++) {
        it = ms_graph->auth_config[e];

        if (it->client_id) {
            cJSON_AddStringToObject(ms_graph_auth, "client_id", it->client_id);
        }
        if (it->tenant_id) {
            cJSON_AddStringToObject(ms_graph_auth, "tenant_id", it->tenant_id);
        }
        if (it->secret_value) {
            cJSON_AddStringToObject(ms_graph_auth, "secret_value", it->secret_value);
        }
        // The FQDN used for querying the API is unique across types, so we can ignore the login FQDN
        if (!strcmp(it->query_fqdn, WM_MS_GRAPH_GLOBAL_API_QUERY_FQDN)) {
            cJSON_AddStringToObject(ms_graph_auth, "api_type", "global");
        } else if (!strcmp(it->query_fqdn, WM_MS_GRAPH_GCC_HIGH_API_QUERY_FQDN)) {
            cJSON_AddStringToObject(ms_graph_auth, "api_type", "gcc-high");
        } else if (!strcmp(it->query_fqdn, WM_MS_GRAPH_DOD_API_QUERY_FQDN)) {
            cJSON_AddStringToObject(ms_graph_auth, "api_type", "dod");
        }
    }
    cJSON_AddItemToObject(ms_graph_info, "api_auth", ms_graph_auth);

    if (ms_graph->resources) {
        cJSON* resource_array = cJSON_CreateArray();
        for (unsigned int resource_num = 0; resource_num < ms_graph->num_resources; resource_num++) {
            cJSON* resource = cJSON_CreateObject();
            if (ms_graph->resources[resource_num].name) {
                cJSON_AddStringToObject(ms_graph_auth, "name", ms_graph->resources[resource_num].name);
            } else {
                cJSON_free(resource);
                continue;
            }
            if (ms_graph->resources[resource_num].relationships) {
                for (unsigned int relationship_num = 0; relationship_num < ms_graph->resources[resource_num].num_relationships; relationship_num++) {
                    if (ms_graph->resources[resource_num].relationships[relationship_num]) {
                        cJSON_AddStringToObject(resource, "relationship", ms_graph->resources[resource_num].relationships[relationship_num]);
                    }
                }
            }
            cJSON_AddItemToArray(resource_array, resource);
        }
        if (cJSON_GetArraySize(resource_array) > 0) {
            cJSON_AddItemToObject(ms_graph_info, "resources", resource_array);
        } else {
            cJSON_free(resource_array);
        }
    }
    cJSON_AddItemToObject(root, "ms_graph", ms_graph_info);

    return root;
}

#endif // WIN32 || defined __linux__ || defined __MACH__
