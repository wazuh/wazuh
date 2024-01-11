/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "active_responses.h"


/**
 * Get json with the data to share on slack from an alert. Example:
 * {
 *  "attachments":  [{
 *          "color":    "warning",
 *          "pretext":  "WAZUH Alert",
 *          "title":    "N/A",
 *          "text": "Jan 28 02:13:23 ubuntu-bionic kernel: [39622.230464] VBoxClient[26081]: ...
 *          "fields":   [{
 *                  "title":    "Agentless Host",
 *                  "value":    "ubuntu-bionic"
 *              }, {
 *                  "title":    "Location",
 *                  "value":    "/var/log/syslog"
 *              }, {
 *                  "title":    "Rule ID",
 *                  "value":    "1010 (level 5)"
 *              }],
 *          "ts":   "1611800004.741250"
 *      }]
 * }
 *
 * @param alert Alert to extract info
 * @return JSON object
 * */
static cJSON *format_output(const cJSON *alert);

int main (int argc, char **argv) {
    (void)argc;
    char *site_url = NULL;
    char *output_str = NULL;
    char *cmd_path = NULL;
    char log_msg[OS_MAXSTR];
    int action = OS_INVALID;
    int return_value = OS_INVALID;
    cJSON *input_json = NULL;
    cJSON *output_json = NULL;

    action = setup_and_check_message(argv, &input_json);
    if ((action != ADD_COMMAND) && (action != DELETE_COMMAND)) {
        return OS_INVALID;
    }

    // Get alert
    const cJSON *alert_json = get_alert_from_json(input_json);
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

    output_json = format_output(alert_json);
    output_str = cJSON_PrintUnformatted(output_json);

    // Execute the command

    // Try with curl
    bool success_command = false;
    if (get_binary_path("curl", &cmd_path) < 0) {
        memset(log_msg, '\0', OS_MAXSTR);
        snprintf(log_msg, OS_MAXSTR -1, "Binary '%s' not found in default paths, the full path will not be used.", cmd_path);
        write_debug_file(argv[0], log_msg);
    }
    char *exec_cmd1[9] = { cmd_path, "-H", "Accept: application/json", "-H", "Content-Type: application/json", "-d", output_str, site_url, NULL };

    wfd_t *wfd = wpopenv(cmd_path, exec_cmd1, W_BIND_STDOUT | W_BIND_STDERR);
    if (wfd) {
        char buffer[4096];
        while (fgets(buffer, sizeof(buffer), wfd->file_out));
        int wp_closefd = wpclose(wfd);
        if ( WIFEXITED(wp_closefd) ) {
            int wstatus = WEXITSTATUS(wp_closefd);
            if (wstatus == 0) {
                success_command = true;
                return_value = OS_SUCCESS;
            }
        }
    }

    if (!success_command) {
        write_debug_file(argv[0], "Unable to run curl, trying with wget...");

        // Try with wget
        os_free(cmd_path);
        if (get_binary_path("wget", &cmd_path) < 0) {
            memset(log_msg, '\0', OS_MAXSTR);
            snprintf(log_msg, OS_MAXSTR -1, "Binary '%s' not found in default paths, the full path will not be used.", cmd_path);
            write_debug_file(argv[0], log_msg);
        }
        char *exec_cmd2[6] = { cmd_path, "--keep-session-cookies", "--post-data", output_str, site_url, NULL };

        wfd = wpopenv(cmd_path, exec_cmd2, W_BIND_STDOUT | W_BIND_STDERR);
        if (wfd) {
            char buffer[4096];
            while (fgets(buffer, sizeof(buffer), wfd->file_out));
            int wp_closefd = wpclose(wfd);
            if ( WIFEXITED(wp_closefd) ) {
                int wstatus = WEXITSTATUS(wp_closefd);
                if (wstatus == 0) {
                    success_command = true;
                    return_value = OS_SUCCESS;
                }
            }
        }
    }

    if (!success_command) {
        write_debug_file(argv[0], "Unable to run wget");
        return_value = OS_INVALID;
    }

    write_debug_file(argv[0], "Ended");

    cJSON_Delete(output_json);
    cJSON_Delete(input_json);
    os_free(output_str);
    os_free(site_url);
    os_free(cmd_path);

    return return_value;
}

static cJSON *format_output(const cJSON *alert) {
    cJSON *rule_json = NULL;
    cJSON *agent_json = NULL;
    cJSON *agentless_json = NULL;
    cJSON *location_json = NULL;
    cJSON *full_log_json = NULL;
    cJSON *rule_description_json = NULL;
    cJSON *alert_id_json = NULL;
    cJSON *root_out = NULL;
    cJSON *root_list = NULL;
    cJSON *fields_list = NULL;
    cJSON *item_objects = NULL;
    cJSON *item_agent = NULL;
    cJSON *item_agentless = NULL;
    cJSON *item_location = NULL;
    cJSON *item_rule = NULL;
    char temp_line[OS_MAXSTR];
    int level = -1;

    root_out = cJSON_CreateObject();
    root_list = cJSON_CreateArray();
    fields_list = cJSON_CreateArray();
    item_objects = cJSON_CreateObject();

    // Detect agent
    agent_json = cJSON_GetObjectItem(alert, "agent");
    if (agent_json && (agent_json->type == cJSON_Object)) {
        cJSON *agent_id_json = NULL;
        cJSON *agent_name_json = NULL;

        item_agent = cJSON_CreateObject();

        // Detect Agent ID
        agent_id_json = cJSON_GetObjectItem(agent_json, "id");

        // Detect Agent name
        agent_name_json = cJSON_GetObjectItem(agent_json, "name");

        memset(temp_line, '\0', OS_MAXSTR);
        snprintf(temp_line, OS_MAXSTR -1, "(%s) - %s",
                                        agent_id_json != NULL ? agent_id_json->valuestring : "N/A",
                                        agent_name_json != NULL ? agent_name_json->valuestring : "N/A"
                                        );

        cJSON_AddStringToObject(item_agent, "title", "Agent");
        cJSON_AddStringToObject(item_agent, "value", temp_line);
        cJSON_AddItemToArray(fields_list, item_agent);
    }

    // Detect agentless
    agentless_json = cJSON_GetObjectItem(alert, "agentless");
    if (agentless_json && (agentless_json->type == cJSON_Object)) {
        cJSON *agentless_host_json = NULL;
        item_agentless = cJSON_CreateObject();

        // Detect Agentless host
        agentless_host_json = cJSON_GetObjectItem(agentless_json, "host");

        cJSON_AddStringToObject(item_agentless, "title", "Agentless Host");
        cJSON_AddStringToObject(item_agentless, "value", agentless_host_json != NULL ? agentless_host_json->valuestring : "N/A");
        cJSON_AddItemToArray(fields_list, item_agentless);
    }

    // Detect location
    location_json = cJSON_GetObjectItem(alert, "location");
    item_location = cJSON_CreateObject();
    cJSON_AddStringToObject(item_location, "title", "Location");
    cJSON_AddStringToObject(item_location, "value", location_json != NULL ? location_json->valuestring : "N/A");
    cJSON_AddItemToArray(fields_list, item_location);

    // Detect Rule
    rule_json = cJSON_GetObjectItem(alert, "rule");
    if (rule_json && (rule_json->type == cJSON_Object)) {
        cJSON *rule_id_json = NULL;
        cJSON *rule_level_json = NULL;
        char str_level[10];

        // Detect Rule ID
        rule_id_json = cJSON_GetObjectItem(rule_json, "id");

        // Detect Rule Level
        memset(str_level, '\0', 10);
        rule_level_json = cJSON_GetObjectItem(rule_json, "level");
        if (rule_level_json && (rule_level_json->type == cJSON_Number)) {
            snprintf(str_level, 9, "%d", rule_level_json->valueint);
            level = rule_level_json->valueint;
        } else {
            snprintf(str_level, 9, "N/A");
        }

        // Detect Rule Description
        rule_description_json = cJSON_GetObjectItem(rule_json, "description");

        memset(temp_line, '\0', OS_MAXSTR);
        snprintf(temp_line, OS_MAXSTR -1, "%s (level %s)",
                                        rule_id_json != NULL ? rule_id_json->valuestring : "N/A",
                                        str_level
                                        );

        item_rule = cJSON_CreateObject();
        cJSON_AddStringToObject(item_rule, "title", "Rule ID");
        cJSON_AddStringToObject(item_rule, "value", temp_line);
        cJSON_AddItemToArray(fields_list, item_rule);
    }

    if (level <= 4) {
        cJSON_AddStringToObject(item_objects, "color", "good");
    } else if (level >= 5 && level <= 7) {
        cJSON_AddStringToObject(item_objects, "color", "warning");
    } else {
        cJSON_AddStringToObject(item_objects, "color", "danger");
    }

    cJSON_AddStringToObject(item_objects, "pretext", "WAZUH Alert");
    cJSON_AddStringToObject(item_objects, "title", rule_description_json != NULL ? rule_description_json->valuestring : "N/A");

    // Detect full log
    full_log_json = cJSON_GetObjectItem(alert, "full_log");
    cJSON_AddStringToObject(item_objects, "text", full_log_json != NULL ? full_log_json->valuestring : "");

    cJSON_AddItemToObject(item_objects, "fields", fields_list);

    alert_id_json = cJSON_GetObjectItem(alert, "id");
    cJSON_AddStringToObject(item_objects, "ts", alert_id_json != NULL ? alert_id_json->valuestring : "");

    cJSON_AddItemToArray(root_list, item_objects);
    cJSON_AddItemToObject(root_out, "attachments", root_list);

    return root_out;
}
