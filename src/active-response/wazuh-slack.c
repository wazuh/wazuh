/* Copyright (C) 2015-2021, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"

#define SITE "https://hooks.slack.com/services/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"
#define DATA "{\"text\": '{\"type\": \"scan_start\"}'}"

static char* format_output_from_alert(cJSON *alert);

int main (int argc, char **argv) {
    (void)argc;
    CURL *curl;
    CURLcode res;
    char errbuf[CURL_ERROR_SIZE];
    char log_msg[LOGSIZE];
    char input[BUFFERSIZE];
    char *site_url;
    char *action;
    cJSON *alert_json = NULL;
    cJSON *input_json = NULL;

    write_debug_file(argv[0], "Starting");

    memset(input, '\0', BUFFERSIZE);
    if (fgets(input, BUFFERSIZE, stdin) == NULL) {
        write_debug_file(argv[0], "Cannot read input from stdin");
        return OS_INVALID;
    }

    write_debug_file(argv[0], input);

    input_json = get_json_from_input(input);
    if (!input_json) {
        write_debug_file(argv[0], "Invalid input format");
        return OS_INVALID;
    }

    action = get_command(input_json);
    if (!action) {
        write_debug_file(argv[0], "Cannot read 'command' from json");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    if (strcmp("add", action)) {
        write_debug_file(argv[0], "Invalid value of 'command'");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Get alert
    alert_json = get_alert_from_json(input_json);
    if (!alert_json) {
        write_debug_file(argv[0], "Cannot read 'alert' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    // Get extra_args
    site_url = get_extra_args_from_json(input_json);
    if (!site_url) {
        write_debug_file(argv[0], "Cannot read 'extra_args' from data");
        cJSON_Delete(input_json);
        return OS_INVALID;
    }

    curl = curl_easy_init();

    curl_easy_setopt(curl, CURLOPT_URL, site_url);

    write_debug_file(argv[0], cJSON_PrintUnformatted(alert_json));


    memset(log_msg, '\0', LOGSIZE);
    snprintf(log_msg, LOGSIZE -1, "{\"text\": \"%s\"}", format_output_from_alert(alert_json));
    //snprintf(log_msg, LOGSIZE -1, "{\"text\": '\"%s\"'}", cJSON_Print(alert_json));

    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, log_msg);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, strlen(log_msg));
    //curl_easy_escape(curl, cJSON_PrintUnformatted(root), strlen(cJSON_PrintUnformatted(root)));

    // Enable SSL check if url is HTTPS
    if(!strncmp(SITE, "https", 5)){
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 1L);
    }

    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, errbuf);
    curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1);
    res = curl_easy_perform(curl);

    switch(res) {
        case CURLE_OK:
            write_debug_file(argv[0], "curl ok");
            break;
        case CURLE_OPERATION_TIMEDOUT:
            write_debug_file(argv[0], errbuf);
            curl_easy_cleanup(curl);
            return OS_INVALID;
        default:
            write_debug_file(argv[0], errbuf);
            curl_easy_cleanup(curl);
            return OS_INVALID;
        }

    curl_easy_cleanup(curl);

    write_debug_file(argv[0], "Ended");


    return OS_SUCCESS;
}

static char* format_output_from_alert(cJSON *alert) {
    char *output = NULL;
    cJSON *data_json = NULL;
    cJSON *rule_json = NULL;
    cJSON *full_log_json = NULL;
    char str_out[LOGSIZE];
    char temp_line[LOGSIZE];

    memset(str_out, '\0', LOGSIZE);
    memset(temp_line, '\0', LOGSIZE);

    // Detect data
    data_json = cJSON_GetObjectItem(alert, "data");
    if (data_json && (data_json->type == cJSON_Object)) {
        cJSON *srcip_json = NULL;
        cJSON *username_json = NULL;

        // Detect srcip
        srcip_json = cJSON_GetObjectItem(data_json, "srcip");
        if (srcip_json && (srcip_json->type == cJSON_String)) {
            memset(temp_line, '\0', LOGSIZE);
            snprintf(temp_line, LOGSIZE -1, "Src IP: %s \n", srcip_json->valuestring);
            strcat(str_out, temp_line);
        }

        // Detect username
        username_json = cJSON_GetObjectItem(data_json, "dstuser");
        if (username_json && (username_json->type == cJSON_String)) {
            memset(temp_line, '\0', LOGSIZE);
            snprintf(temp_line, LOGSIZE -1, "User: %s \n", username_json->valuestring);
            strcat(str_out, temp_line);
        }
    }

    // Detect Rule
    rule_json = cJSON_GetObjectItem(alert, "rule");
    if (rule_json && (rule_json->type == cJSON_Object)) {
        cJSON *rule_id_json = NULL;
        cJSON *rule_level_json = NULL;
        cJSON *rule_description_json = NULL;
        char str_level[10];

        // Detect Rule ID
        rule_id_json = cJSON_GetObjectItem(rule_json, "id");

        // Detect Rule Level
        memset(str_level, '\0', 10);
        rule_level_json = cJSON_GetObjectItem(rule_json, "level");
        if (rule_level_json && (rule_level_json->type == cJSON_Number)) {
            snprintf(str_level, 9, "%d", rule_level_json->valueint);
        } else {
            snprintf(str_level, 9, "-");
        }

        // Detect Rule Description
        rule_description_json = cJSON_GetObjectItem(rule_json, "description");

        memset(temp_line, '\0', LOGSIZE);
        snprintf(temp_line, LOGSIZE -1, "Rule: %s (level %s) -> '%s'\n",
                                        rule_id_json != NULL ? rule_id_json->valuestring : "-",
                                        str_level,
                                        rule_description_json != NULL ? rule_description_json->valuestring : "-"
                                        );
        strcat(str_out, temp_line);
    }

    // Detect full log
    full_log_json = cJSON_GetObjectItem(alert, "full_log");
    if (full_log_json) {
        strcat(str_out, full_log_json->valuestring);
        strcat(str_out, "\n");
    }

    os_strdup(str_out, output);

    return output;

}
