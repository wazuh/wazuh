/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * July 5, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb_global_helpers.h"
#include "defs.h"
#include "wazuhdb_op.h"

#ifdef WIN32
#define chown(x, y, z) 0
#endif

static const char *global_db_commands[] = {
    [WDB_INSERT_AGENT] = "global insert-agent %s",
    [WDB_INSERT_AGENT_GROUP] = "global insert-agent-group %s",
    [WDB_UPDATE_AGENT_NAME] = "global update-agent-name %s",
    [WDB_UPDATE_AGENT_DATA] = "global update-agent-data %s",
    [WDB_UPDATE_AGENT_KEEPALIVE] = "global update-keepalive %s",
    [WDB_UPDATE_AGENT_CONNECTION_STATUS] = "global update-connection-status %s",
    [WDB_UPDATE_AGENT_STATUS_CODE] = "global update-status-code %s",
    [WDB_GET_ALL_AGENTS] = "global get-all-agents last_id %d",
    [WDB_FIND_AGENT] = "global find-agent %s",
    [WDB_GET_AGENT_INFO] = "global get-agent-info %d",
    [WDB_GET_AGENT_LABELS] = "global get-labels %d",
    [WDB_SELECT_AGENT_NAME] = "global select-agent-name %d",
    [WDB_SELECT_AGENT_GROUP] = "global select-agent-group %d",
    [WDB_FIND_GROUP] = "global find-group %s",
    [WDB_SELECT_GROUPS] = "global select-groups",
    [WDB_DELETE_AGENT] = "global delete-agent %d",
    [WDB_DELETE_GROUP] = "global delete-group %s",
    [WDB_SET_AGENT_GROUPS] = "global set-agent-groups %s",
    [WDB_RESET_AGENTS_CONNECTION] = "global reset-agents-connection %s",
    [WDB_GET_AGENTS_BY_CONNECTION_STATUS] = "global get-agents-by-connection-status %d %s",
    [WDB_GET_AGENTS_BY_CONNECTION_STATUS_AND_NODE] = "global get-agents-by-connection-status %d %s %s %d",
    [WDB_DISCONNECT_AGENTS] = "global disconnect-agents %d %d %s",
    [WDB_GET_DISTINCT_AGENT_GROUP] = "global get-distinct-groups %s"
};

int wdb_insert_agent(int id,
                     const char *name,
                     const char *ip,
                     const char *register_ip,
                     const char *internal_key,
                     const char *group,
                     int keep_date,
                     int *sock) {
    int result = 0;
    time_t date_add = 0;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;

    if(keep_date) {
        date_add = get_agent_date_added(id);
    } else {
        time(&date_add);
    }

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddNumberToObject(data_in, "id", id);
    cJSON_AddStringToObject(data_in, "name", name);
    cJSON_AddStringToObject(data_in, "ip", ip);
    cJSON_AddStringToObject(data_in, "register_ip", register_ip);
    cJSON_AddStringToObject(data_in, "internal_key", internal_key);
    cJSON_AddStringToObject(data_in, "group", group);
    cJSON_AddNumberToObject(data_in, "date_add", date_add);

    data_in_str = cJSON_PrintUnformatted(data_in);
    cJSON_Delete(data_in);
    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_INSERT_AGENT], data_in_str);
    os_free(data_in_str);

    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    return result;
}

int wdb_insert_group(const char *name, int *sock) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_INSERT_AGENT_GROUP], name);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

int wdb_update_agent_name(int id, const char *name, int *sock) {
    int result = 0;
    cJSON *data_in = NULL;
    char* data_in_str = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddNumberToObject(data_in, "id", id);
    cJSON_AddStringToObject(data_in, "name", name);
    data_in_str = cJSON_PrintUnformatted(data_in);
    cJSON_Delete(data_in);
    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_UPDATE_AGENT_NAME], data_in_str);
    os_free(data_in_str);

    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    return result;
}

int wdb_update_agent_data(agent_info_data *agent_data, int *sock) {
    int result = 0;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    char *payload = NULL;
    int aux_sock = -1;

    if (!agent_data) {
        mdebug1("Invalid data provided to set in global.db.");
        return OS_INVALID;
    }

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddNumberToObject(data_in, "id", agent_data->id);
    cJSON_AddStringToObject(data_in, "version", agent_data->version);
    cJSON_AddStringToObject(data_in, "config_sum", agent_data->config_sum);
    cJSON_AddStringToObject(data_in, "merged_sum", agent_data->merged_sum);
    cJSON_AddStringToObject(data_in, "manager_host", agent_data->manager_host);
    cJSON_AddStringToObject(data_in, "node_name", agent_data->node_name);
    cJSON_AddStringToObject(data_in, "agent_ip", agent_data->agent_ip);
    cJSON_AddStringToObject(data_in, "labels", agent_data->labels);
    cJSON_AddStringToObject(data_in, "connection_status", agent_data->connection_status);
    cJSON_AddStringToObject(data_in, "sync_status", agent_data->sync_status);
    cJSON_AddStringToObject(data_in, "group_config_status", agent_data->group_config_status);

    if (agent_data->osd) {
        cJSON_AddStringToObject(data_in, "os_name", agent_data->osd->os_name);
        cJSON_AddStringToObject(data_in, "os_version", agent_data->osd->os_version);
        cJSON_AddStringToObject(data_in, "os_major", agent_data->osd->os_major);
        cJSON_AddStringToObject(data_in, "os_minor", agent_data->osd->os_minor);
        cJSON_AddStringToObject(data_in, "os_codename", agent_data->osd->os_codename);
        cJSON_AddStringToObject(data_in, "os_platform", agent_data->osd->os_platform);
        cJSON_AddStringToObject(data_in, "os_build", agent_data->osd->os_build);
        cJSON_AddStringToObject(data_in, "os_uname", agent_data->osd->os_uname);
        cJSON_AddStringToObject(data_in, "os_arch", agent_data->osd->os_arch);
    }

    data_in_str = cJSON_PrintUnformatted(data_in);

    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, global_db_commands[WDB_UPDATE_AGENT_DATA], data_in_str);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    cJSON_Delete(data_in);
    os_free(data_in_str);
    os_free(wdbquery);
    os_free(wdboutput);

    return result;
}

int wdb_update_agent_keepalive(int id, const char *connection_status, const char *sync_status, int *sock) {
    int result = 0;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    char *payload = NULL;
    int aux_sock = -1;

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddNumberToObject(data_in, "id", id);
    cJSON_AddStringToObject(data_in, "connection_status", connection_status);
    cJSON_AddStringToObject(data_in, "sync_status", sync_status);
    data_in_str = cJSON_PrintUnformatted(data_in);

    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, global_db_commands[WDB_UPDATE_AGENT_KEEPALIVE], data_in_str);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    cJSON_Delete(data_in);
    os_free(data_in_str);
    os_free(wdbquery);
    os_free(wdboutput);

    return result;
}

int wdb_update_agent_connection_status(int id, const char *connection_status, const char *sync_status, int *sock, agent_status_code_t status_code) {
    int result = 0;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    char *payload = NULL;
    int aux_sock = -1;

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddNumberToObject(data_in, "id", id);
    cJSON_AddStringToObject(data_in, "connection_status", connection_status);
    cJSON_AddStringToObject(data_in, "sync_status", sync_status);
    cJSON_AddNumberToObject(data_in, "status_code", status_code);
    data_in_str = cJSON_PrintUnformatted(data_in);

    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, global_db_commands[WDB_UPDATE_AGENT_CONNECTION_STATUS], data_in_str);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    cJSON_Delete(data_in);
    os_free(data_in_str);
    os_free(wdbquery);
    os_free(wdboutput);

    return result;
}

int wdb_update_agent_status_code(int id, agent_status_code_t status_code, const char *version, const char *sync_status, int *sock) {
    int result = 0;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    char *payload = NULL;
    int aux_sock = -1;

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddNumberToObject(data_in, "id", id);
    cJSON_AddNumberToObject(data_in, "status_code", status_code);
    if (version != NULL) {
        char wazuh_version[OS_SIZE_128 + 1] = "";
        snprintf(wazuh_version, OS_SIZE_128, "%s %s", __ossec_name, version);
        cJSON_AddStringToObject(data_in, "version", wazuh_version);
    }
    cJSON_AddStringToObject(data_in, "sync_status", sync_status);
    data_in_str = cJSON_PrintUnformatted(data_in);

    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, global_db_commands[WDB_UPDATE_AGENT_STATUS_CODE], data_in_str);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    cJSON_Delete(data_in);
    os_free(data_in_str);
    os_free(wdbquery);
    os_free(wdboutput);

    return result;
}

int* wdb_get_all_agents(bool include_manager, int *sock) {
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int last_id = include_manager ? -1 : 0;
    int *array = NULL;
    int len = 0;
    wdbc_result status = WDBC_DUE;
    int aux_sock = -1;

    while (status == WDBC_DUE) {
        // Query WazuhDB
        snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_GET_ALL_AGENTS], last_id);
        if (wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput)) == 0) {
            status = wdb_parse_chunk_to_int(wdboutput, &array, "id", &last_id, &len);
        }
        else {
            status = WDBC_ERROR;
        }
    }

    if (status == WDBC_ERROR) {
        os_free(array);
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return array;
}

rb_tree* wdb_get_all_agents_rbtree(bool include_manager, int *sock) {
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int last_id = include_manager ? -1 : 0;
    rb_tree *tree = NULL;
    wdbc_result status = WDBC_DUE;
    int aux_sock = -1;

    tree = rbtree_init();

    while (status == WDBC_DUE) {
        // Query WazuhDB
        snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_GET_ALL_AGENTS], last_id);
        if (wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput)) == 0) {
            status = wdb_parse_chunk_to_rbtree(wdboutput, &tree, "id", &last_id);
        }
        else {
            status = WDBC_ERROR;
        }
    }

    if (status == WDBC_ERROR) {
        merror("Error querying Wazuh DB to get agent's IDs.");
        rbtree_destroy(tree);
        tree = NULL;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return tree;
}

int wdb_find_agent(const char *name, const char *ip, int *sock) {
    int output = OS_INVALID;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    cJSON *root = NULL;
    cJSON *json_id = NULL;
    int aux_sock = -1;

    if (!name || !ip) {
        mdebug1("Empty agent name or ip when trying to get agent ID.");
        return OS_INVALID;
    }

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddStringToObject(data_in, "name", name);
    cJSON_AddStringToObject(data_in, "ip", ip);

    data_in_str = cJSON_PrintUnformatted(data_in);
    cJSON_Delete(data_in);
    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_FIND_AGENT], data_in_str);
    os_free(data_in_str);

    root = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!root) {
        merror("Error querying Wazuh DB for agent ID.");
        return OS_INVALID;
    }

    json_id = cJSON_GetObjectItem(root->child,"id");
    if (cJSON_IsNumber(json_id)) {
        output = json_id->valueint;
    }
    else {
        output = -2;
    }

    cJSON_Delete(root);
    return output;
}

cJSON* wdb_get_agent_info(int id, int *sock) {
    cJSON *root = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int aux_sock = -1;

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_commands[WDB_GET_AGENT_INFO], id);
    root = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!root) {
        merror("Error querying Wazuh DB to get the agent's %d information.", id);
        return NULL;
    }

    return root;
}

cJSON* wdb_get_agent_labels(int id, int *sock) {
    cJSON *root = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_GET_AGENT_LABELS], id);
    root = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!root) {
        merror("Error querying Wazuh DB to get the agent's %d labels.", id);
        return NULL;
    }

    return root;
}

char* wdb_get_agent_name(int id, int *sock) {
    char *output = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_name = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_SELECT_AGENT_NAME], id);
    root = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!root) {
        merror("Error querying Wazuh DB to get the agent's %d name.", id);
        return NULL;
    }

    json_name = cJSON_GetObjectItem(root->child,"name");
    if (cJSON_IsString(json_name) && json_name->valuestring != NULL) {
        os_strdup(json_name->valuestring, output);
    } else {
        os_strdup("", output);
    }

    cJSON_Delete(root);
    return output;
}

char* wdb_get_agent_group(int id, int *sock) {
    char *output = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_group = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_SELECT_AGENT_GROUP], id);
    root = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!root) {
        merror("Error querying Wazuh DB to get the agent's %d group.", id);
        return NULL;
    }

    json_group = cJSON_GetObjectItem(root->child,"group");
    if (cJSON_IsString(json_group) && json_group->valuestring != NULL) {
        os_strdup(json_group->valuestring, output);
    }

    cJSON_Delete(root);
    return output;
}

int wdb_find_group(const char *name, int *sock) {
    int output = OS_INVALID;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_group = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_FIND_GROUP], name);
    root = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!root) {
        merror("Error querying Wazuh DB to get the agent group id.");
        return OS_INVALID;
    }

    json_group = cJSON_GetObjectItem(root->child,"id");
    output = cJSON_IsNumber(json_group) ? json_group->valueint : OS_INVALID;

    cJSON_Delete(root);
    return output;
}

int wdb_update_groups(const char *dirname, int *sock) {
    cJSON *root = NULL;
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int aux_sock = -1;

    if (!dirname) {
        return OS_INVALID;
    }

    root = wdbc_query_parse_json(sock?sock:&aux_sock, global_db_commands[WDB_SELECT_GROUPS], wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to update groups.");
        if (!sock) {
            wdbc_close(&aux_sock);
        }
        return OS_INVALID;
    }

    cJSON *item = NULL;
    cJSON_ArrayForEach(item, root) {
        cJSON *json_name = cJSON_GetObjectItem(item, "name");

        if (cJSON_IsString(json_name) && json_name->valuestring != NULL) {
            /* Check if the group exists in dir */
            char group_path[PATH_MAX + 1] = {0};
            DIR *dp = NULL;

            if (snprintf(group_path, PATH_MAX + 1, "%s/%s", dirname, json_name->valuestring) > PATH_MAX) {
                merror("At wdb_update_groups(): path too long.");
                continue;
            }

            dp = wopendir(group_path);

            /* Group doesn't exists anymore, delete it */
            if (!dp) {
                wdb_remove_group_db(json_name->valuestring, sock?sock:&aux_sock);
            }
            else {
                closedir(dp);
            }
        }
    }

    cJSON_Delete(root);

    /* Add new groups from the folder /etc/shared if they dont exists on database */
    DIR *dp = NULL;
    struct dirent *dirent = NULL;

    if (!(dp = wopendir(dirname))) {
        merror("Couldn't open directory '%s': %s.", dirname, strerror(errno));
        if (!sock) {
            wdbc_close(&aux_sock);
        }
        return OS_INVALID;
    }

    const char *current_directory = ".";
    const char *parent_directory = "..";
    while ((dirent = readdir(dp))) {
        if (strcmp(current_directory, dirent->d_name) && strcmp(parent_directory, dirent->d_name)) {
            char path[PATH_MAX];
            snprintf(path, PATH_MAX, "%s/%s", dirname, dirent->d_name);

            if (!IsDir(path)) {
                if (wdb_find_group(dirent->d_name, sock?sock:&aux_sock) <= 0) {
                    wdb_insert_group(dirent->d_name, sock?sock:&aux_sock);
                }
            }
        }
    }
    closedir(dp);

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return OS_SUCCESS;
}

int wdb_remove_agent(int id, int *sock) {
    int result = 0 ;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;
    int* query_sock = sock?sock:&aux_sock;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_DELETE_AGENT], id);
    result = wdbc_query_ex(query_sock, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return result;
}

int wdb_remove_group_db(const char *name, int *sock) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_DELETE_GROUP], name);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

int wdb_set_agent_groups_csv(int id, char* groups_csv, char* mode, char* sync_status, int *sock) {
    char** groups_array = w_string_split(groups_csv, ",", 0);
    int ret = wdb_set_agent_groups(id, groups_array, mode, sync_status, sock);
    free_strarray(groups_array);
    return ret;
}

int wdb_set_agent_groups(int id, char** groups_array, char* mode, char* sync_status, int *sock) {
    int aux_sock = -1;

    if (!groups_array || !mode) {
        mdebug1("Invalid params to set the agent groups %02d", id);
        return OS_INVALID;
    }
    cJSON* j_data_in = cJSON_CreateObject();
    if (!j_data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddStringToObject(j_data_in, "mode", mode);
    if (sync_status) {
        cJSON_AddStringToObject(j_data_in, "sync_status", sync_status);
    }
    cJSON* j_agents_array = cJSON_AddArrayToObject(j_data_in, "data");
    cJSON* j_agent_info = cJSON_CreateObject();
    cJSON_AddItemToArray(j_agents_array, j_agent_info);
    cJSON_AddNumberToObject(j_agent_info, "id", id);
    cJSON* groups = cJSON_AddArrayToObject(j_agent_info, "groups");
    for (int i=0; groups_array[i]; i++) {
        cJSON_AddItemToArray(groups, cJSON_CreateString(groups_array[i]));
    }

    char* data_in_str = cJSON_PrintUnformatted(j_data_in);
    cJSON_Delete(j_data_in);
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_SET_AGENT_GROUPS], data_in_str);
    os_free(data_in_str);

    int result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));
    if (!sock) {
        wdbc_close(&aux_sock);
    }

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, NULL)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

int wdb_reset_agents_connection(const char *sync_status, int *sock) {
    int result = OS_SUCCESS;
    char *wdbquery = NULL;
    char *wdboutput = NULL;
    int aux_sock = -1;

    os_malloc(WDBQUERY_SIZE, wdbquery);
    snprintf(wdbquery, WDBQUERY_SIZE, global_db_commands[WDB_RESET_AGENTS_CONNECTION], sync_status);

    os_malloc(WDBOUTPUT_SIZE, wdboutput);
    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, WDBOUTPUT_SIZE);

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, NULL)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
            break;
    }

    os_free(wdbquery);
    os_free(wdboutput);

    return result;
}

int* wdb_get_agents_by_connection_status(const char* connection_status, int *sock) {
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int last_id = 0;
    int *array = NULL;
    int len = 0;
    wdbc_result status = WDBC_DUE;
    int aux_sock = -1;

    while (status == WDBC_DUE) {
        // Query WazuhDB
        snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_GET_AGENTS_BY_CONNECTION_STATUS], last_id, connection_status);
        if (wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput)) == 0) {
            status = wdb_parse_chunk_to_int(wdboutput, &array, "id", &last_id, &len);
        }
        else {
            status = WDBC_ERROR;
        }
    }

    if (status == WDBC_ERROR) {
        os_free(array);
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return array;
}

wdbc_result wdb_parse_chunk_to_int(char* input, int** output, const char* item, int* last_item, int* last_size) {
    int len = last_size ? *last_size : 0;
    int _last_item = 0;
    char* payload = NULL;

    if (!output) {
        return WDBC_ERROR;
    }

    wdbc_result status = wdbc_parse_result(input, &payload);
    if (status == WDBC_OK || status == WDBC_DUE) {
        cJSON* response = cJSON_Parse(payload);
        if (response) {
            //Realloc new size
            os_realloc(*output, sizeof(int)*(len+cJSON_GetArraySize(response)+1), *output);
            //Append items to output array
            cJSON* agent = NULL;
            cJSON_ArrayForEach(agent, response) {
                cJSON* json_item = cJSON_GetObjectItem(agent, item);
                if (cJSON_IsNumber(json_item)) {
                    (*output)[len] = json_item->valueint;
                    _last_item = json_item->valueint;
                    len++;
                }
            }
            cJSON_Delete(response);
        }
        else {
            status = WDBC_ERROR;
        }
    }

    //Always finalize the array
    if(*output) {
        (*output)[len] = -1;
    }

    if (last_size) *last_size = len;
    if (last_item) *last_item = _last_item;

    return status;
}

wdbc_result wdb_parse_chunk_to_rbtree(char* input, rb_tree** output, const char* item, int* last_item) {
    int _last_item = 0;
    char* payload = NULL;

    if (output == NULL || *output == NULL) {
        mdebug1("Invalid RB tree.");
        return WDBC_ERROR;
    }

    if (item == NULL) {
        mdebug1("Invalid item.");
        return WDBC_ERROR;
    }

    wdbc_result status = wdbc_parse_result(input, &payload);
    if (status == WDBC_OK || status == WDBC_DUE) {
        cJSON* response = cJSON_Parse(payload);
        if (response != NULL) {
            //Add items to RB tree
            cJSON* agent = NULL;
            cJSON_ArrayForEach(agent, response) {
                cJSON* json_item = cJSON_GetObjectItem(agent, item);
                if (cJSON_IsNumber(json_item)) {
                    char c_agent_id[OS_SIZE_16];
                    snprintf(c_agent_id, OS_SIZE_16, "%03d", json_item->valueint);
                    rbtree_insert(*output, c_agent_id, &(json_item->valueint));
                    _last_item = json_item->valueint;
                }
            }
            cJSON_Delete(response);
        }
        else {
            status = WDBC_ERROR;
        }
    }

    if (last_item) *last_item = _last_item;

    return status;
}

int* wdb_disconnect_agents(int keepalive, const char *sync_status, int *sock) {
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int last_id = 0;
    int *array = NULL;
    int len = 0;
    wdbc_result status = WDBC_DUE;
    int aux_sock = -1;

    while (status == WDBC_DUE) {
        // Query WazuhDB
        snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_DISCONNECT_AGENTS], last_id, keepalive, sync_status);
        if (wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput)) == 0) {
            status = wdb_parse_chunk_to_int(wdboutput, &array, "id", &last_id, &len);
        }
        else {
            status = WDBC_ERROR;
        }
    }

    if (status == WDBC_ERROR) {
        os_free(array);
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return array;
}

time_t get_agent_date_added(int agent_id) {
    char path[PATH_MAX + 1] = {0};
    char line[OS_BUFFER_SIZE] = {0};
    char * sep;
    FILE *fp;
    struct tm t;
    time_t t_of_sec;

    snprintf(path, PATH_MAX, "%s", TIMESTAMP_FILE);

    fp = wfopen(path, "r");

    if (!fp) {
        return 0;
    }

    while (fgets(line, OS_BUFFER_SIZE, fp)) {
        if (sep = strchr(line, ' '), sep) {
            *sep = '\0';
        } else {
            continue;
        }

        if(atoi(line) == agent_id){
            /* Extract date */
            char **data;
            char * date = NULL;
            *sep = ' ';

            data = OS_StrBreak(' ', line, 5);

            if(data == NULL) {
                fclose(fp);
                return 0;
            }

            /* Date is 3 and 4 */
            wm_strcat(&date,data[3], ' ');
            wm_strcat(&date,data[4], ' ');

            if(date == NULL) {
                fclose(fp);
                free_strarray(data);
                return 0;
            }

            char *endl = strchr(date, '\n');

            if (endl) {
                *endl = '\0';
            }

            if (sscanf(date, "%d-%d-%d %d:%d:%d",&t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec) < 6) {
                merror("Invalid date format in file '%s' for agent '%d'", TIMESTAMP_FILE, agent_id);
                free(date);
                free_strarray(data);
                fclose(fp);
                return 0;
            }
            t.tm_year -= 1900;
            t.tm_mon -= 1;
            t.tm_isdst = -1;
            t_of_sec = mktime(&t);

            free(date);
            fclose(fp);
            free_strarray(data);

            return t_of_sec;
        }
    }

    fclose(fp);
    return 0;
}

int* wdb_get_agents_ids_of_current_node(const char* connection_status, int *sock, int last_id, int limit) {
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int *array = NULL;
    int len = 0;
    wdbc_result status = WDBC_DUE;
    char *node_name = NULL;
    int aux_sock = -1;

    node_name = get_node_name();
    while (status == WDBC_DUE) {
        // Query WazuhDB
        snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_GET_AGENTS_BY_CONNECTION_STATUS_AND_NODE], last_id, connection_status, node_name, limit);
        if (wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput)) == 0) {
            status = wdb_parse_chunk_to_int(wdboutput, &array, "id", &last_id, &len);
        }
        else {
            status = WDBC_ERROR;
        }
    }
    os_free(node_name);

    if (status == WDBC_ERROR) {
        os_free(array);
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return array;
}

wdbc_result wdb_parse_chunk_to_json_by_string_item(char* input, cJSON** output_json, const char *item, char **last_item_value) {
    char* payload = NULL;

    if (output_json == NULL || !cJSON_IsArray(*output_json)) {
        mdebug1("Invalid JSON array.");
        return WDBC_ERROR;
    }

    if (item == NULL) {
        mdebug1("Invalid item.");
        return WDBC_ERROR;
    }

    wdbc_result status = wdbc_parse_result(input, &payload);
    if (status == WDBC_OK || status == WDBC_DUE) {
        cJSON* response = cJSON_Parse(payload);
        if (response != NULL) {
            int array_size = cJSON_GetArraySize(response);
            if (array_size > 0) {
                cJSON_AddItemToArray(*output_json, response);
                cJSON *last_item_json = cJSON_GetObjectItem(cJSON_GetArrayItem(response, array_size - 1), item);
                if (last_item_json && cJSON_GetStringValue(last_item_json) && last_item_value) {
                    os_strdup(cJSON_GetStringValue(last_item_json), *last_item_value);
                }
            } else {
                cJSON_Delete(response);
            }
        } else {
            status = WDBC_ERROR;
        }
    }

    return status;
}

cJSON* wdb_get_distinct_agent_groups(int *sock) {
    cJSON *root = NULL;
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char wdbquery[WDBQUERY_SIZE] = "";
    int aux_sock = -1;
    wdbc_result status = WDBC_DUE;
    char *tmp_last_hash_group = NULL;

    root = cJSON_CreateArray();

    os_strdup("", tmp_last_hash_group);
    while (status == WDBC_DUE) {
        snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_GET_DISTINCT_AGENT_GROUP], tmp_last_hash_group);
        if (wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput)) == 0) {
            os_free(tmp_last_hash_group);
            status = wdb_parse_chunk_to_json_by_string_item(wdboutput, &root, "group_hash", &tmp_last_hash_group);
        }
        else {
            status = WDBC_ERROR;
        }
    }
    os_free(tmp_last_hash_group);

    if (status == WDBC_ERROR) {
        merror("Error querying Wazuh DB to get agent's groups.");
        cJSON_Delete(root);
        root = NULL;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return root;
}
