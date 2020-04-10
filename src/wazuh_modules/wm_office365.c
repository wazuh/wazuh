/*
 * Wazuh module for Microsoft Office 365
 * Copyright (C) 2015-2020, Wazuh Inc.
 * March 30, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wmodules.h"

static const char* WM_OFFICE365_RESOURCE = "https://manage.office.com/";
static const char* WM_OFFICE365_LOGIN = "https://login.microsoftonline.com/";
static int queue_fd;

static void* wm_office365_main(wm_office365_t* office365_config);    // Module main function. It won't return
static void wm_office365_destroy(wm_office365_t* office365_config);  // Destroy data
cJSON* wm_office365_dump(const wm_office365_t* office365_config);

// Microsoft Office 365 module context definition
const wm_context WM_OFFICE365_CONTEXT = {
    "office365",
    (wm_routine)wm_office365_main,
    (wm_routine)(void*)wm_office365_destroy,
    (cJSON* (*)(const void*))wm_office365_dump
};

// Obtain a token to get access to the Microsoft Office 365 management activity API
char* obtain_access_token(wm_office365_t* office365_config) {
    // Dynamic memory allocation variables
    char* url = NULL;
    char* payload = NULL;
    char* token = NULL; // It is the output. No need to be freed
    whttp_response_t* response;
    cJSON *cjson_body;
    cJSON *cjson_token; // Points to a cjson_body element. No need to be freed

    // Build the payload with the client information
    wm_strcat(&payload, "client_id=", '\0');
    wm_strcat(&payload, office365_config->client_id, '\0');
    wm_strcat(&payload, "&scope=", '\0');
    wm_strcat(&payload, WM_OFFICE365_RESOURCE, '\0');
    wm_strcat(&payload, ".default", '\0');
    wm_strcat(&payload, "&grant_type=client_credentials", '\0');
    wm_strcat(&payload, "&client_secret=", '\0');
    wm_strcat(&payload, office365_config->client_secret, '\0');

    // Build the url from the login and tenant information
    wm_strcat(&url, WM_OFFICE365_LOGIN, '\0');
    wm_strcat(&url, office365_config->tenant_id, '\0');
    wm_strcat(&url, "/oauth2/v2.0/token", '\0');

    // Perform request
    response = whttp_request("POST", url, NULL, payload, office365_config->timeout);
    os_free(url);
    os_free(payload);

    // Check if there is a response
    if (!response) {
        mterror(WM_OFFICE365_LOGTAG, "Unknown error requesting Microsoft Office 365 API token.");
        return NULL;
    }

    // Check response status code
    if (response->status_code != 200) {
        mterror(WM_OFFICE365_LOGTAG, "Bad response requesting Microsoft Office 365 API token: %lu code.", response->status_code);
        free(response->body);
        free(response->header);
        free(response);

        return NULL;
    }

    // Parse the response body
    cjson_body = cJSON_Parse(response->body);
    os_free(response->body);
    os_free(response->header);
    os_free(response);

    // Check the cjson_body object
    if (cjson_body) {
        // Get the token from the response
        cjson_token = cJSON_GetObjectItemCaseSensitive(cjson_body, "access_token");

        // If it contains a string 
        if (cJSON_IsString(cjson_token)) {
            mtinfo(WM_OFFICE365_LOGTAG, "Successfully fetched the Microsoft Office 365 management activity API token.");
            token = cjson_token->valuestring;

            // Properly detach valuestring from the cJSON object
            cjson_token->valuestring = NULL;
        } else {
            mterror(WM_OFFICE365_LOGTAG, "Could not fetch the Microsoft Office 365 management activity API token.");
            cJSON_Delete(cjson_body);

            return NULL;
        }
    } else {
        mterror(WM_OFFICE365_LOGTAG, "Could not parse response as a cJSON.");

        return NULL;
    }

    cJSON_Delete(cjson_body);

    return token;
}

// Perform a request to Microsoft Office 365 management activity API
char* make_api_request(wm_office365_t* office365_config, const char* method, const char* url, const char* token) {
    // Dynamic memory allocation variables
    char* header = NULL;
    char* response_body = NULL; // It is the output. No need to be freed
    char* next_page_body = NULL;
    char* next_page_url = NULL;  // Points to part of the output. No need to be freed
    char* header_line = NULL;  // Points to part of the response header. No need to be freed
    char* header_save_ptr = NULL;  // Points to part of the response header. No need to be freed
    whttp_response_t* response = NULL;

    // Build bearer header
    wm_strcat(&header, "Content-Type: application/json", '\n');
    wm_strcat(&header, "Authorization: Bearer ", '\n');
    wm_strcat(&header, token, '\0');

    // Perform the HTTP request
    if (strcmp(method, "GET") == 0) {
        mtdebug1(WM_OFFICE365_LOGTAG, "GET request to %s", url);
        response = whttp_request("GET", url, header, NULL, office365_config->timeout);
    } else if (strcmp(method, "POST") == 0) {
        mtdebug1(WM_OFFICE365_LOGTAG, "POST request to %s", url);
        response = whttp_request("POST", url, header, NULL, office365_config->timeout);
    } else {
        mterror(WM_OFFICE365_LOGTAG, "Invalid HTTP method. Valid one are GET or POST.");
        free(header);

        return NULL;
    }

    os_free(header);

    // Check if there is a response
    if (!response) {
        mterror(WM_OFFICE365_LOGTAG, "Unknown error performing Microsoft Office 365 API request.");

        return NULL;
    }

    // Check response status code
    if (response->status_code == 200) {
        // Assign body to function output
        response_body = response->body;

        // Detach body from response
        response->body = NULL;

        // If this is a GET request then check the response headers
        if (strcmp(method, "GET") == 0) {
            // Loop every header
            for (header_line = strtok_r(response->header, "\n", &header_save_ptr); header_line; header_line = strtok_r(NULL, "\n", &header_save_ptr)) {
                // If it contains NextPageUri
                if (header_line && strstr(header_line, "NextPageUri")) {
                    // Get the next page URL
                    strtok(header_line, " ");
                    next_page_url = strtok(NULL, " ");

                    // Replace the jump line with end of line
                    next_page_url[strlen(next_page_url) - 1] = 0;

                    mtdebug1(WM_OFFICE365_LOGTAG, "New data page detected: %s.", next_page_url);

                    // Request next page
                    next_page_body = make_api_request(office365_config, "GET", next_page_url, token);
                    os_free(next_page_url);

                    // Append next page body to current body
                    if (next_page_body) {
                        wm_strcat(&response_body, next_page_body, '\0');
                        os_free(next_page_body);
                    }
                }
            }
        }

        free(response->header);
        free(response);

        return response_body;
    } else {
        mterror(WM_OFFICE365_LOGTAG, "Bad response performing Microsoft Office 365 API request: %lu code.", response->status_code);
        free(response->header);
        free(response->body);
        free(response);

        return NULL;
    }
}

// Start a content type subscription
char* start_content_type_subscription(wm_office365_t* office365_config, const char* subscription_name, const char* token) {
    // Dynamic memory allocation variables
    char* url = NULL;
    char* response = NULL; // It is the output. No need to be freed

    // Build the url from the resource and client information
    wm_strcat(&url, WM_OFFICE365_RESOURCE, '\0');
    wm_strcat(&url, "api/v1.0/", '\0');
    wm_strcat(&url, office365_config->client_id, '\0');
    wm_strcat(&url, "/activity/feed/subscriptions/start?contentType=", '\0');
    wm_strcat(&url, subscription_name, '\0');

    // Perform API request
    response = make_api_request(office365_config, "POST", url, token);
    os_free(url);

    // Check if there is a response
    if (response) {
        mtinfo(WM_OFFICE365_LOGTAG, "Successfully started %s content type subscription.", subscription_name);
        return response;
    } else {
        mterror(WM_OFFICE365_LOGTAG, "Error while starting %s content type subscription.", subscription_name);
        return NULL;
    }
}

// Send events to agentd queue
void send_events(const cJSON* events) {
    // Static/automatic memory allocation variables
    int usec = 1000000 / wm_max_eps;

    // Dynamic memory allocation variables
    char* raw_event = NULL;
    cJSON *event = NULL;
    cJSON* element = NULL; // Points to an events element. No need to be freed

    // Iterate events
    cJSON_ArrayForEach(element, events) {
        // Create event object
        event = cJSON_CreateObject();

        // Duplicate element and add it to the event object under the office365 key
        cJSON_AddItemToObject(event, "office365", cJSON_Duplicate(element, true));

        // Parse the cJSON event
        raw_event = cJSON_PrintUnformatted(event);
        cJSON_Delete(event);

        // Send the parsed event to agentd
        wm_sendmsg(usec, queue_fd, raw_event, WM_OFFICE365_CONTEXT.name, LOCALFILE_MQ);
        free(raw_event);
    }
}

// Get the available blobs for the specified subscription
cJSON* get_subscription_blobs(wm_office365_t* office365_config, const char* subscription, const char* token) {
    // Static/automatic memory allocation variables
    char start_time[20];
    char end_time[20];
    time_t current_time;
    struct tm* time_info;

    // Dynamic memory allocation variables
    char* url = NULL;
    char* raw_blobs = NULL;
    cJSON* blobs = NULL; // It is the output. No need to be freed

    // Build start and end times for the request, make sure the time is UTC
    current_time = time(NULL);
    time_info = gmtime(&current_time);
    strftime(end_time, sizeof(end_time), "%Y-%m-%dT%H:%M:%S", time_info);
    current_time -= office365_config->interval;
    time_info = gmtime(&current_time);
    strftime(start_time, sizeof(start_time), "%Y-%m-%dT%H:%M:%S", time_info);

    // Build the url from the resource and client information
    wm_strcat(&url, WM_OFFICE365_RESOURCE, '\0');
    wm_strcat(&url, "api/v1.0/", '\0');
    wm_strcat(&url, office365_config->client_id, '\0');
    wm_strcat(&url, "/activity/feed/subscriptions/content?contentType=", '\0');
    wm_strcat(&url, subscription, '\0');
    wm_strcat(&url, "&startTime=", '\0');
    wm_strcat(&url, start_time, '\0');
    wm_strcat(&url, "&endTime=", '\0');
    wm_strcat(&url, end_time, '\0');

    // Parse the response
    raw_blobs = make_api_request(office365_config, "GET", url, token);
    os_free(url);

    // Check if there is a response
    if (!raw_blobs) {
        mterror(WM_OFFICE365_LOGTAG, "Empty response while fetching %s content type blobs.", subscription);
        return NULL;
    }

    // Parse raw_blobs into cJSON
    blobs = cJSON_Parse(raw_blobs);
    os_free(raw_blobs);

    if (!blobs) {
        mterror(WM_OFFICE365_LOGTAG, "Error while parsing %s content type blobs.", subscription);
        return NULL;
    }

    return blobs;
}

// Send events from blob
int send_events_from_blob(wm_office365_t* office365_config, const cJSON* blob, const char* token) {
    // Dynamic memory allocation variables
    char* raw_events = NULL;
    cJSON* events = NULL;
    cJSON* content_uri = NULL; // Points to part of the blob. No need to be freed

    content_uri = cJSON_GetObjectItemCaseSensitive(blob, "contentUri");

    // If there's a valid content uri
    if (cJSON_IsString(content_uri)) {
        // Request the events contained in it
        raw_events = make_api_request(office365_config, "GET", content_uri->valuestring, token);

        // If there's something in the response
        if (raw_events) {
            // Parse it to cJSON
            events = cJSON_Parse(raw_events);
            os_free(raw_events);

            if (events) {
                // Send the JSON parsed events
                send_events(events);
                cJSON_Delete(events);
            } else {
                mterror(WM_OFFICE365_LOGTAG, "Error while parsing content uri events.");
                return 0;
            }
        }
    } else {
        mterror(WM_OFFICE365_LOGTAG, "Invalid content URI in blob.");
        return 0;
    }

    return 1;
}

// Office 365 module main function. It won't return.
static void* wm_office365_main(wm_office365_t* office365_config) {
    // Static/automatic memory allocation variables
    unsigned int i;
    time_t time_start;
    time_t time_sleep = 0;
    char client_secret[OS_MAXSTR];

    // Dynamic memory allocation variables
    char* token = NULL;
    char* response = NULL;
    cJSON* blobs = NULL;
    cJSON* blob = NULL; // No need to be freed
    FILE* client_secret_fd = NULL;
    wm_office365_subscription_t* iter; // No need to be freed

    if (!office365_config->enabled) {
        mtwarn(WM_OFFICE365_LOGTAG, "Module is disabled. Exiting.");
        pthread_exit(NULL);
    }

    mtinfo(WM_OFFICE365_LOGTAG, "Module started.");

    // Connect to socket
    for (i = 0; (queue_fd = StartMQ(DEFAULTQPATH, WRITE)) < 0 && i < WM_MAX_ATTEMPTS; i++) {
        wm_delay(1000 * WM_MAX_WAIT);
    }

    if (i == WM_MAX_ATTEMPTS) {
        mterror(WM_OFFICE365_LOGTAG, "Can't connect to queue. Exiting.");
        pthread_exit(NULL);
    }

    // Read client secret from path
    if (office365_config->client_secret_path) {
        mtdebug2(WM_OFFICE365_LOGTAG, "Opening file secret file at %s.", office365_config->client_secret_path);

        client_secret_fd = wfopen(office365_config->client_secret_path, "r");

        // If the file was successfully opened
        if (client_secret_fd) {
            // Read its contents
            if (fgets(client_secret, OS_MAXSTR, client_secret_fd) != NULL) {
                office365_config->client_secret = client_secret;
            } else {
                mterror(WM_OFFICE365_LOGTAG, "Error reading secret file. Exiting.");
                pthread_exit(NULL);
            }

            // Close the file descriptor 
            fclose(client_secret_fd);
        } else {
            mterror(WM_OFFICE365_LOGTAG, "Can't open client secret file. Exiting.");
            pthread_exit(NULL);
        }
    }

    // Calculate next scan time
    if (!office365_config->run_on_start) {
        time_start = time(NULL);

        // On first run, take into account the configured interval
        if (office365_config->state.next_time == 0) {
            office365_config->state.next_time = time_start + office365_config->interval;
        }

        if (office365_config->state.next_time > time_start) {
            mtinfo(WM_OFFICE365_LOGTAG, "Waiting interval to start fetching.");
            time_sleep = office365_config->state.next_time - time_start;
            wm_delay(1000 * time_sleep);
        }
    }

    // Main loop
    while (1) {
        // Get time and execute
        time_start = time(NULL);

        // Obtain token
        mtinfo(WM_OFFICE365_LOGTAG, "Requesting Microsoft Office 365 API token...");
        token = obtain_access_token(office365_config);

        // Proceed if a token was obtained
        if (token) {
            // For every configured subscription
            for (iter = office365_config->subscriptions; iter; iter = iter->next) {
                // Start the subscription
                mtinfo(WM_OFFICE365_LOGTAG, "Starting %s subscription...", iter->name);
                response = start_content_type_subscription(office365_config, iter->name, token);

                // Check if there is a response
                if (response) {
                    os_free(response);

                    // Get subscription blobs
                    mtinfo(WM_OFFICE365_LOGTAG, "Fetching %s subscription blobs...", iter->name);
                    blobs = get_subscription_blobs(office365_config, iter->name, token);

                    // Check if there are blobs
                    if (blobs) {
                        // Iterate blobs and send events
                        mtinfo(WM_OFFICE365_LOGTAG, "Fetching %s events...", iter->name);
                        cJSON_ArrayForEach(blob, blobs) {
                            send_events_from_blob(office365_config, blob, token);
                        }

                        cJSON_Delete(blobs);
                    } else {
                        office365_config->state.error = 1;
                        if (!office365_config->skip_on_error) break;
                    }
                } else {
                    office365_config->state.error = 1;
                    if (!office365_config->skip_on_error) break;
                }
            }

            mtinfo(WM_OFFICE365_LOGTAG, "Fetching events finished.");
            os_free(token);
        } else {
            office365_config->state.error = 1;
        }

        // Check error and skip_on_error
        if (office365_config->state.error != 0) {
            if (office365_config->skip_on_error) {
                mtwarn(WM_OFFICE365_LOGTAG, "Error during scan. Skip on error is enabled. Waiting for the next scan.");
            } else {
                mterror(WM_OFFICE365_LOGTAG, "Error during scan. Skip on error is disabled. Exiting.");
                pthread_exit(NULL);
            }
        }

        // Update state
        if (office365_config->interval) {
            time_sleep = time(NULL) - time_start;

            if ((time_t)office365_config->interval >= time_sleep) {
                time_sleep = office365_config->interval - time_sleep;
                office365_config->state.next_time = office365_config->interval + time_start;
            } else {
                mtwarn(WM_OFFICE365_LOGTAG, "Interval overtaken.");
                time_sleep = office365_config->state.next_time = 0;
            }

            if (wm_state_io(WM_OFFICE365_CONTEXT.name, WM_IO_WRITE, &office365_config->state, sizeof(office365_config->state)) < 0)
                mterror(WM_OFFICE365_LOGTAG, "Couldn't save running state.");
        }

        // If time_sleep = 0, yield CPU
        wm_delay(1000 * time_sleep);
    }

    return NULL;
}

// Destroy data
void wm_office365_destroy(wm_office365_t *office365_config) {
    free(office365_config);
}

// Dump configuration to cJSON
cJSON *wm_office365_dump(const wm_office365_t *office365_config) {
    cJSON *root = cJSON_CreateObject();
    cJSON *wm_office365 = cJSON_CreateObject();

    if (office365_config->enabled) cJSON_AddStringToObject(wm_office365, "enabled", "yes"); else cJSON_AddStringToObject(wm_office365, "enabled", "no");
    if (office365_config->run_on_start) cJSON_AddStringToObject(wm_office365, "run_on_start", "yes"); else cJSON_AddStringToObject(wm_office365, "run_on_start", "no");
    if (office365_config->skip_on_error) cJSON_AddStringToObject(wm_office365, "skip_on_error", "yes"); else cJSON_AddStringToObject(wm_office365, "skip_on_error", "no");
    if (office365_config->tenant_id) cJSON_AddStringToObject(wm_office365, "tenant_id", office365_config->tenant_id);
    if (office365_config->client_id) cJSON_AddStringToObject(wm_office365, "client_id", office365_config->client_id);
    if (office365_config->client_secret_path) {
        cJSON_AddStringToObject(wm_office365, "client_secret_path", office365_config->client_secret_path);
    } else if (office365_config->client_secret) {
        cJSON_AddStringToObject(wm_office365, "client_secret", office365_config->client_secret);
    }
    if (office365_config->subscriptions) {
        wm_office365_subscription_t *iter;
        cJSON *subscriptions = cJSON_CreateArray();
        for (iter = office365_config->subscriptions; iter; iter = iter->next) {
            cJSON *subscription = cJSON_CreateObject();
            if (iter->name) cJSON_AddStringToObject(subscription, "name", iter->name);
            cJSON_AddItemToArray(subscriptions, subscription);
        }
        if (cJSON_GetArraySize(subscriptions) > 0) {
            cJSON_AddItemToObject(wm_office365, "subscriptions", subscriptions);
        } else {
            cJSON_free(subscriptions);
        }
    }

    cJSON_AddItemToObject(root, "office365", wm_office365);

    return root;
}
