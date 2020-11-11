/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 5, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "defs.h"
#include "wazuhdb_op.h"

#ifdef WIN32
#define chown(x, y, z) 0
#endif

#define WDBQUERY_SIZE OS_BUFFER_SIZE
#define WDBOUTPUT_SIZE OS_MAXSTR

static const char *global_db_commands[] = {
    [WDB_INSERT_AGENT] = "global insert-agent %s",
    [WDB_INSERT_AGENT_GROUP] = "global insert-agent-group %s",
    [WDB_INSERT_AGENT_BELONG] = "global insert-agent-belong %s",
    [WDB_UPDATE_AGENT_NAME] = "global update-agent-name %s",
    [WDB_UPDATE_AGENT_DATA] = "global update-agent-data %s",
    [WDB_UPDATE_AGENT_KEEPALIVE] = "global update-keepalive %s",
    [WDB_UPDATE_AGENT_STATUS] = "global update-agent-status %s",
    [WDB_UPDATE_AGENT_GROUP] = "global update-agent-group %s",
    [WDB_SET_AGENT_LABELS] = "global set-labels %d %s",
    [WDB_GET_ALL_AGENTS] = "global get-all-agents last_id %d",
    [WDB_GET_AGENTS_BY_KEEPALIVE] = "global get-agents-by-keepalive condition %s %d last_id %d",
    [WDB_FIND_AGENT] = "global find-agent %s",
    [WDB_GET_AGENT_INFO] = "global get-agent-info %d",
    [WDB_GET_AGENT_LABELS] = "global get-labels %d",
    [WDB_SELECT_AGENT_NAME] = "global select-agent-name %d",
    [WDB_SELECT_AGENT_GROUP] = "global select-agent-group %d",
    [WDB_SELECT_AGENT_STATUS] = "global select-agent-status %d",
    [WDB_SELECT_KEEPALIVE] = "global select-keepalive %s %s",
    [WDB_FIND_GROUP] = "global find-group %s",
    [WDB_SELECT_GROUPS] = "global select-groups",
    [WDB_DELETE_AGENT] = "global delete-agent %d",
    [WDB_DELETE_GROUP] = "global delete-group %s",
    [WDB_DELETE_AGENT_BELONG] = "global delete-agent-belong %d",
    [WDB_DELETE_GROUP_BELONG] = "global delete-group-belong %s"
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
            if (WDBC_OK == wdbc_parse_result(wdboutput, &payload)) {
                result = wdb_create_agent_db(id, name);
            }
            else {
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

int wdb_update_agent_belongs(int id_group, int id_agent, int *sock) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;
    char *data_in_str = NULL;
    cJSON *data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddNumberToObject(data_in, "id_group", id_group);
    cJSON_AddNumberToObject(data_in, "id_agent", id_agent);

    data_in_str = cJSON_PrintUnformatted(data_in);
    cJSON_Delete(data_in);
    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_INSERT_AGENT_BELONG], data_in_str);
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
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
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
    cJSON_AddStringToObject(data_in, "sync_status", agent_data->sync_status);

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
    cJSON_Delete(data_in);
    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_UPDATE_AGENT_DATA], data_in_str);
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

int wdb_update_agent_keepalive(int id, const char *sync_status, int *sock) {
    int result = 0;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
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
    cJSON_AddStringToObject(data_in, "sync_status", sync_status);

    data_in_str = cJSON_PrintUnformatted(data_in);
    cJSON_Delete(data_in);
    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_UPDATE_AGENT_KEEPALIVE], data_in_str);
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

int wdb_set_agent_status(int id_agent, int status, int *sock) {
    int result = 0;
    const char *str_status = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    cJSON *data_in = NULL;
    char *data_in_str = NULL;
    int aux_sock = -1;

    switch (status) {
    case WDB_AGENT_EMPTY:
        str_status = "empty";
        break;
    case WDB_AGENT_PENDING:
        str_status = "pending";
        break;
    case WDB_AGENT_UPDATED:
        str_status = "updated";
        break;
    default:
        return OS_INVALID;
    }

    data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddNumberToObject(data_in, "id", id_agent);
    cJSON_AddStringToObject(data_in, "status", str_status);

    data_in_str = cJSON_PrintUnformatted(data_in);
    cJSON_Delete(data_in);
    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_UPDATE_AGENT_STATUS], data_in_str);
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
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

int wdb_update_agent_group(int id, char *group, int *sock) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;
    char *data_in_str = NULL;
    cJSON *data_in = cJSON_CreateObject();

    if (!data_in) {
        mdebug1("Error creating data JSON for Wazuh DB.");
        return OS_INVALID;
    }

    cJSON_AddNumberToObject(data_in, "id", id);
    cJSON_AddStringToObject(data_in, "group", group);

    data_in_str = cJSON_PrintUnformatted(data_in);
    cJSON_Delete(data_in);
    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_UPDATE_AGENT_GROUP], data_in_str);
    os_free(data_in_str);

    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK != wdbc_parse_result(wdboutput, &payload)) {
                mdebug1("Global DB Error reported in the result of the query");
                result = OS_INVALID;
            }
            else if (wdb_update_agent_multi_group(id, group, sock?sock:&aux_sock) < 0) {
                result = OS_INVALID;
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            if (!sock) {
                wdbc_close(&aux_sock);
            }
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            if (!sock) {
                wdbc_close(&aux_sock);
            }
            return OS_INVALID;
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return result;
}

int wdb_set_agent_labels(int id, const char *labels, int *sock) {
    int result = 0;
    // Making use of a big buffer for the query because it
    // will contain all the keys and values.
    // The output will be just a JSON OK.
    char wdbquery[OS_MAXSTR] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_SET_AGENT_LABELS], id, labels);

    result = wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    switch (result){
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
            // Parse result
            char* payload = NULL;
            status = wdbc_parse_result(wdboutput, &payload);
            if (status == WDBC_OK || status == WDBC_DUE) {
                const char delim = ',';
                const char sdelim[] = { delim, '\0' };
                //Realloc new size
                int new_len = os_strcnt(payload, delim)+1;
                os_realloc(array, sizeof(int)*(len+new_len+1), array);
                //Append IDs to array
                char* agent_id = NULL;
                char *savedptr = NULL;
                for (agent_id = strtok_r(payload, sdelim, &savedptr); agent_id; agent_id = strtok_r(NULL, sdelim, &savedptr)) {
                    array[len] = atoi(agent_id);
                    last_id = array[len];
                    len++;
                }
            }
        }
        else {
            status = WDBC_ERROR;
        }
    }
    if (status == WDBC_OK) {
        array[len] = -1;
    }
    else {
        os_free(array);
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return array;
}

int* wdb_get_agents_by_keepalive(const char* condition, int keepalive, bool include_manager, int *sock) {
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int last_id = include_manager ? -1 : 0;
    int *array = NULL;
    int len = 0;
    wdbc_result status = WDBC_DUE;
    int aux_sock = -1;

    while (status == WDBC_DUE) {
        // Query WazuhDB
        snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_GET_AGENTS_BY_KEEPALIVE], condition, keepalive, last_id);
        if (wdbc_query_ex(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput)) == 0) {
            // Parse result
            char* payload = NULL;
            status = wdbc_parse_result(wdboutput, &payload);
            if (status == WDBC_OK || status == WDBC_DUE) {
                const char delim = ',';
                const char sdelim[] = { delim, '\0' };
                //Realloc new size
                int new_len = os_strcnt(payload, delim)+1;
                os_realloc(array, sizeof(int)*(len+new_len+1), array);
                //Append IDs to array
                char* agent_id = NULL;
                char *savedptr = NULL;
                for (agent_id = strtok_r(payload, sdelim, &savedptr); agent_id; agent_id = strtok_r(NULL, sdelim, &savedptr)) {
                    array[len] = atoi(agent_id);
                    last_id = array[len];
                    len++;
                }
            }
        }
        else {
            status = WDBC_ERROR;
        }
    }

    if (status == WDBC_OK) {
        array[len] = -1;
    }
    else {
        os_free(array);
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return array;
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

int wdb_get_agent_status(int id_agent, int *sock) {
    int output = -1;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_status = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_SELECT_AGENT_STATUS], id_agent);
    root = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!root) {
        merror("Error querying Wazuh DB to get the agent status.");
        return OS_INVALID;
    }

    json_status = cJSON_GetObjectItem(root->child,"status");
    if (cJSON_IsString(json_status) && json_status->valuestring != NULL) {
        output = !strcmp(json_status->valuestring, "empty") ? WDB_AGENT_EMPTY : !strcmp(json_status->valuestring, "pending") ? WDB_AGENT_PENDING : WDB_AGENT_UPDATED;
    } else {
        output = OS_INVALID;
    }

    cJSON_Delete(root);
    return output;
}

time_t wdb_get_agent_keepalive(const char *name, const char *ip, int *sock){
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    time_t output = 0;
    cJSON *root = NULL;
    cJSON *json_keepalive = NULL;
    int aux_sock = -1;

    if (!name || !ip) {
        mdebug1("Empty agent name or ip when trying to get last keepalive.");
        return OS_INVALID;
    }

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_SELECT_KEEPALIVE], name, ip);
    root = wdbc_query_parse_json(sock?sock:&aux_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    if (!root) {
        merror("Error querying Wazuh DB to get the last agent keepalive.");
        return OS_INVALID;
    }

    json_keepalive = cJSON_GetObjectItem(root->child,"last_keepalive");
    output = cJSON_IsNumber(json_keepalive) ? json_keepalive->valueint : 0;

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
    int result = OS_SUCCESS;
    int n = 0;
    int i = 0;
    char **array = NULL;
    cJSON *json_name = NULL;
    cJSON *item = NULL;
    cJSON *root = NULL;
    char wdboutput[WDBOUTPUT_SIZE] = "";
    int aux_sock = -1;
    int* query_sock = sock?sock:&aux_sock;

    root = wdbc_query_parse_json(query_sock, global_db_commands[WDB_SELECT_GROUPS], wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to update groups.");
        if (!sock) {
            wdbc_close(&aux_sock);
        }
        return OS_INVALID;
    }

    item = root->child;
    os_calloc(cJSON_GetArraySize(root) + 1 , sizeof(char *),array);

    while (item)
    {
        json_name = cJSON_GetObjectItem(item,"name");

        if(cJSON_IsString(json_name) && json_name->valuestring != NULL ){
            os_strdup(json_name->valuestring, array[n]);
            n++;
        }

        item=item->next;
    }

    array[n] = NULL;
    cJSON_Delete(root);

    for (i=0; array[i]; i++) {
        /* Check if the group exists in dir */
        char group_path[PATH_MAX + 1] = {0};
        DIR *dp;

        if (snprintf(group_path, PATH_MAX + 1, "%s/%s", dirname,array[i]) > PATH_MAX) {
            merror("At wdb_update_groups(): path too long.");
            continue;
        }

        dp = opendir(group_path);

        /* Group doesnt exists anymore, delete it */
        if (!dp) {
            if (wdb_remove_group_db((char *)array[i], query_sock) < 0) {
                free_strarray(array);
                if (!sock) {
                    wdbc_close(&aux_sock);
                }
                return OS_INVALID;
            }
        } else {
            closedir(dp);
        }
    }

    free_strarray(array);

    /* Add new groups from the folder /etc/shared if they dont exists on database */
    DIR *dir;
    struct dirent *dirent = NULL;

    if (!(dir = opendir(dirname))) {
        merror("Couldn't open directory '%s': %s.", dirname, strerror(errno));
        if (!sock) {
            wdbc_close(&aux_sock);
        }
        return OS_INVALID;
    }

    while ((dirent = readdir(dir))) {
        if (dirent->d_name[0] != '.') {
            char path[PATH_MAX];
            snprintf(path,PATH_MAX,"%s/%s",dirname,dirent->d_name);

            if (!IsDir(path)) {
                if (wdb_find_group(dirent->d_name, query_sock) <= 0){
                    wdb_insert_group(dirent->d_name, query_sock);
                }
            }
        }
    }
    closedir(dir);

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return result;
}

int wdb_remove_agent(int id, int *sock) {
    int result = 0 ;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    char *name = NULL;
    int aux_sock = -1;
    int* query_sock = sock?sock:&aux_sock;

    // Getting the agent's name before removing it from global.db
    name = wdb_get_agent_name(id, query_sock);

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_DELETE_AGENT], id);
    result = wdbc_query_ex(query_sock, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            if (WDBC_OK == wdbc_parse_result(wdboutput, &payload)) {
                result = wdb_delete_agent_belongs(id, query_sock);

                if ((OS_SUCCESS == result) && name &&
                     OS_INVALID == wdb_remove_agent_db(id, name)) {
                     mdebug1("Unable to remove agent DB: %d - %s", id, name);
                }
            }
            else {
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

    os_free(name);

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

    if (OS_INVALID == wdb_remove_group_from_belongs_db(name, sock?sock:&aux_sock)) {
        merror("At wdb_remove_group_from_belongs_db(): couldn't delete '%s' from 'belongs' table.", name);
        if (!sock) {
            wdbc_close(&aux_sock);
        }
        return OS_INVALID;
    }

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

int wdb_delete_agent_belongs(int id, int *sock) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_DELETE_AGENT_BELONG], id);
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

int wdb_remove_group_from_belongs_db(const char *name, int *sock) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *payload = NULL;
    int aux_sock = -1;

    snprintf(wdbquery, sizeof(wdbquery), global_db_commands[WDB_DELETE_GROUP_BELONG], name);
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

int wdb_create_agent_db(int id, const char *name) {
    const char *ROOT = "root";
    char path[OS_FLSIZE + 1];
    char buffer[4096];
    FILE *source;
    FILE *dest;
    size_t nbytes;
    int result = 0;
    uid_t uid;
    gid_t gid;

    if (!name)
        return -1;

    snprintf(path, OS_FLSIZE, "%s/%s", WDB_DIR, WDB_PROF_NAME);

    if (!(source = fopen(path, "r"))) {
        mdebug1("Profile database not found, creating.");

        if (wdb_create_profile(path) < 0)
            return -1;

        // Retry to open

        if (!(source = fopen(path, "r"))) {
            merror("Couldn't open profile '%s'.", path);
            return -1;
        }
    }

    snprintf(path, OS_FLSIZE, "%s%s/agents/%03d-%s.db", isChroot() ? "/" : "", WDB_DIR, id, name);

    if (!(dest = fopen(path, "w"))) {
        fclose(source);
        merror("Couldn't create database '%s'.", path);
        return -1;
    }

    while (nbytes = fread(buffer, 1, 4096, source), nbytes) {
        if (fwrite(buffer, 1, nbytes, dest) != nbytes) {
            result = -1;
            break;
        }
    }

    fclose(source);
    if (fclose(dest) == -1 || result < 0) {
        merror("Couldn't write/close file '%s' completely.", path);
        return -1;
    }

    uid = Privsep_GetUser(ROOT);
    gid = Privsep_GetGroup(GROUPGLOBAL);

    if (uid == (uid_t) - 1 || gid == (gid_t) - 1) {
        merror(USER_ERROR, ROOT, GROUPGLOBAL, strerror(errno), errno);
        return -1;
    }

    if (chown(path, uid, gid) < 0) {
        merror(CHOWN_ERROR, path, errno, strerror(errno));
        return -1;
    }

    if (chmod(path, 0660) < 0) {
        merror(CHMOD_ERROR, path, errno, strerror(errno));
        return -1;
    }

    return 0;
}

int wdb_remove_agent_db(int id, const char * name) {
    char path[PATH_MAX];
    char path_aux[PATH_MAX];

    snprintf(path, PATH_MAX, "%s%s/agents/%03d-%s.db", isChroot() ? "/" : "", WDB_DIR, id, name);

    if (!remove(path)) {
        snprintf(path_aux, PATH_MAX, "%s%s/agents/%03d-%s.db-shm", isChroot() ? "/" : "", WDB_DIR, id, name);
        if (remove(path_aux) < 0) {
            mdebug2(DELETE_ERROR, path_aux, errno, strerror(errno));
        }
        snprintf(path_aux, PATH_MAX, "%s%s/agents/%03d-%s.db-wal", isChroot() ? "/" : "", WDB_DIR, id, name);
        if (remove(path_aux) < 0) {
            mdebug2(DELETE_ERROR, path_aux, errno, strerror(errno));
        }
        return OS_SUCCESS;
    } else
        return OS_INVALID;
}

int wdb_update_agent_multi_group(int id, char *group, int *sock) {
    int aux_sock = -1;
    int* query_sock = sock?sock:&aux_sock;

    /* Wipe out the agent multi groups relation for this agent */
    if (wdb_delete_agent_belongs(id, query_sock) < 0) {
        return OS_INVALID;
    }

    /* Update the belongs table if multi group */
    const char delim[2] = ",";

    if (group) {
        char *multi_group;
        char *save_ptr = NULL;

        multi_group = strchr(group, MULTIGROUP_SEPARATOR);

        if (multi_group) {
            /* Get the first group */
            multi_group = strtok_r(group, delim, &save_ptr);

            while (multi_group != NULL) {
                /* Update de groups table */
                int id_group = wdb_find_group(multi_group, query_sock);

                if(id_group <= 0 && OS_SUCCESS == wdb_insert_group(multi_group, query_sock)) {
                    id_group = wdb_find_group(multi_group, query_sock);
                }

                if (OS_SUCCESS != wdb_update_agent_belongs(id_group, id, query_sock)) {
                    if (!sock) {
                        wdbc_close(&aux_sock);
                    }
                    return OS_INVALID;
                }

                multi_group = strtok_r(NULL, delim, &save_ptr);
            }
        } else {
            /* Update de groups table */
            int id_group = wdb_find_group(group, query_sock);

            if (id_group <= 0 && OS_SUCCESS == wdb_insert_group(group, query_sock)) {
                id_group = wdb_find_group(group, query_sock);
            }

            if (OS_SUCCESS != wdb_update_agent_belongs(id_group, id, query_sock)) {
                if (!sock) {
                    wdbc_close(&aux_sock);
                }
                return OS_INVALID;
            }
        }
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return OS_SUCCESS;
}

int wdb_agent_belongs_first_time(int *sock){
    int i;
    char *group;
    int *agents;
    int aux_sock = -1;
    int* query_sock = sock?sock:&aux_sock;

    if ((agents = wdb_get_all_agents(FALSE, query_sock))) {

        for (i = 0; agents[i] != -1; i++) {
            group = wdb_get_agent_group(agents[i], query_sock);

            if (group) {
                wdb_update_agent_multi_group(agents[i],group, query_sock);
                os_free(group);
            }
        }
        os_free(agents);
    }

    if (!sock) {
        wdbc_close(&aux_sock);
    }

    return OS_SUCCESS;
}

time_t get_agent_date_added(int agent_id) {
    char path[PATH_MAX + 1] = {0};
    char line[OS_BUFFER_SIZE] = {0};
    char * sep;
    FILE *fp;
    struct tm t;
    time_t t_of_sec;

    snprintf(path, PATH_MAX, "%s", isChroot() ? TIMESTAMP_FILE : DEFAULTDIR TIMESTAMP_FILE);

    fp = fopen(path, "r");

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
            t.tm_isdst = 0;
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
