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

static const char *global_db_queries[] = {
    [SQL_UPDATE_AGENT_NAME] = "global sql UPDATE agent SET name = %Q WHERE id = %d;",
    [SQL_UPDATE_AGENT_VERSION] = "global sql UPDATE agent SET os_name = %Q, os_version = %Q, os_major = %Q, os_minor = %Q, os_codename = %Q, os_platform = %Q, os_build = %Q, os_uname = %s, os_arch = %Q, version = %Q, config_sum = %Q, merged_sum = %Q, manager_host = %Q, node_name = %Q, last_keepalive = STRFTIME('%s', 'NOW'), sync_status = %d WHERE id = %d;",
    [SQL_UPDATE_AGENT_VERSION_IP] = "global sql UPDATE agent SET os_name = %Q, os_version = %Q, os_major = %Q, os_minor = %Q, os_codename = %Q, os_platform = %Q, os_build = %Q, os_uname = %s, os_arch = %Q, version = %Q, config_sum = %Q, merged_sum = %Q, manager_host = %Q, node_name = %Q, last_keepalive = STRFTIME('%s', 'NOW'), ip = %Q, sync_status = %d WHERE id = %d;",
    [SQL_GET_AGENT_LABELS] = "global get-labels %d",
    [SQL_SET_AGENT_LABELS] = "global set-labels %d %s",
    [SQL_UPDATE_AGENT_KEEPALIVE] = "global sql UPDATE agent SET last_keepalive = STRFTIME('%s', 'NOW'), sync_status = %d WHERE id = %d;",
    [SQL_DELETE_AGENT] = "global sql DELETE FROM agent WHERE id = %d;",
    [SQL_SELECT_AGENT] = "global sql SELECT name FROM agent WHERE id = %d;",
    [SQL_SELECT_AGENT_GROUP] = "global sql SELECT `group` FROM agent WHERE id = %d;",
    [SQL_SELECT_AGENTS] = "global sql SELECT id FROM agent WHERE id != 0;",
    [SQL_FIND_AGENT] = "global sql SELECT id FROM agent WHERE name = '%s' AND (register_ip = '%s' OR register_ip LIKE '%s' || '/_%');",
    [SQL_SELECT_FIM_OFFSET] = "global sql SELECT fim_offset FROM agent WHERE id = %d;",
    [SQL_SELECT_REG_OFFSET] = "global sql SELECT reg_offset FROM agent WHERE id = %d;",
    [SQL_UPDATE_FIM_OFFSET] = "global sql UPDATE agent SET fim_offset = %lu WHERE id = %d;",
    [SQL_UPDATE_REG_OFFSET] = "global sql UPDATE agent SET reg_offset = %lu WHERE id = %d;",
    [SQL_SELECT_AGENT_STATUS] = "global sql SELECT status FROM agent WHERE id = %d;",
    [SQL_UPDATE_AGENT_STATUS] = "global sql UPDATE agent SET status = %Q WHERE id = %d;",
    [SQL_UPDATE_AGENT_GROUP] = "global sql UPDATE agent SET `group` = %Q WHERE id = %d;",
    [SQL_FIND_GROUP] = "global sql SELECT id FROM `group` WHERE name = %Q;",
    [SQL_INSERT_AGENT_GROUP] = "global sql INSERT INTO `group` (name) VALUES(%Q);",
    [SQL_INSERT_AGENT_BELONG] = "global sql INSERT INTO belongs (id_group, id_agent) VALUES(%d, %d);",
    [SQL_DELETE_AGENT_BELONG] = "global sql DELETE FROM belongs WHERE id_agent = %d",
    [SQL_DELETE_GROUP_BELONG] = "global sql DELETE FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = %Q );", 
    [SQL_DELETE_GROUP] = "global sql DELETE FROM `group` WHERE name = %Q;",
    [SQL_SELECT_GROUPS] = "global sql SELECT name FROM `group`;",
    [SQL_SELECT_KEEPALIVE] = "global sql SELECT last_keepalive FROM agent WHERE name = '%s' AND (register_ip = '%s' OR register_ip LIKE '%s' || '/_%');"
};

int wdb_sock_agent = -1;

static const char *global_db_accesses[] = {
    [WDB_INSERT_AGENT] = "global insert-agent %s"
};


int wdb_insert_agent(int id, const char *name, const char *ip, const char *register_ip, const char *internal_key, const char *group, int keep_date) {
    int result = 0;
    time_t date_add = 0;
    cJSON *data_in = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

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

    snprintf(wdbquery, sizeof(wdbquery), global_db_accesses[WDB_INSERT_AGENT], cJSON_PrintUnformatted(data_in));

    cJSON_Delete(data_in);

    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            result = wdb_create_agent_db(id, name);
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    return result;
}

/* Update agent name. It doesn't rename agent DB file. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_name(int id, const char *name) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_UPDATE_AGENT_NAME], name, id);
    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    return result;
}

/* Update agent version. Sends a request to Wazuh-DB. Returns 1 or -1 on error. */
int wdb_update_agent_version (int id,
                             const char *os_name,
                             const char *os_version,
                             const char *os_major,
                             const char *os_minor,
                             const char *os_codename,
                             const char *os_platform,
                             const char *os_build,
                             const char *os_uname,
                             const char *os_arch,
                             const char *version,
                             const char *config_sum,
                             const char *merged_sum,
                             const char *manager_host,
                             const char *node_name,
                             const char *agent_ip,
                             wdb_sync_status_t sync_status) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char os_uname_format[OS_BUFFER_SIZE] = "";
    char *keepalive_format = "%s";

    // os_uname fails with %Q flag
    if (!os_uname) {
        snprintf(os_uname_format, sizeof(os_uname_format),"NULL");
    }
    else {
        snprintf(os_uname_format, sizeof(os_uname_format),"'%s'", os_uname);
    }

    if(agent_ip) {
        sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_UPDATE_AGENT_VERSION_IP],
        os_name, os_version, os_major, os_minor, os_codename, os_platform, os_build, os_uname_format,
        os_arch, version, config_sum, merged_sum, manager_host, node_name, keepalive_format, agent_ip, sync_status, id);
    } else {
        sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_UPDATE_AGENT_VERSION],
        os_name, os_version, os_major, os_minor, os_codename, os_platform, os_build, os_uname_format,
        os_arch, version, config_sum, merged_sum, manager_host, node_name, keepalive_format, sync_status, id);
    }

    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            result = 1;
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    return result;
}

/**
 * @brief Returns a JSON with all the agent's labels.
 * 
 * @param[in] id Id of the agent for whom the labels are requested.
 * @return JSON* with the labels on success or NULL on failure.
 */
cJSON* wdb_get_agent_labels(int id) {
    cJSON *root = NULL;
    // Making use of a big buffer for the output because
    // it will contain all the keys and values.
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_MAXSTR] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_GET_AGENT_LABELS], id);
    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to get the agent's %d labels.", id);
        return NULL;
    }

    return root;
}

/**
 * @brief Update agent's labels.
 * 
 * @param[in] id Id of the agent for whom the labels must be updated.
 * @param[in] labels String with the key-values separated by EOL.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_set_agent_labels(int id, const char *labels) {
    int result = 0;
    // Making use of a big buffer for the query because it
    // will contain all the keys and values.
    // The output will be just a JSON OK.
    char wdbquery[OS_MAXSTR] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_SET_AGENT_LABELS], id, labels);

    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result){
        case OS_SUCCESS:
            break;
        case OS_INVALID:
            mdebug1("GLobal DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("GLobal DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    return result;
}

/* Update agent's last keepalive time. Sends a request to Wazuh-DB. Returns OS_SUCCESS or -1 on error. */
int wdb_update_agent_keepalive(int id, wdb_sync_status_t sync_status) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char *keepalive_format = "%s";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_UPDATE_AGENT_KEEPALIVE], keepalive_format, sync_status, id);

    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    return result;
}

/* Delete agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_agent(int id) {
    int result = 0 ;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    char * name = NULL;

    name = wdb_agent_name(id);
    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_DELETE_AGENT], id);
    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            wdb_delete_agent_belongs(id);
            result = name ? wdb_remove_agent_db(id, name) : OS_INVALID;
            if(result == OS_INVALID){
                mdebug1("Unable to remove agent DB: %d - %s ", id, name);
            }
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            break;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            result = OS_INVALID;
    }

    os_free(name);
    return result;
}

/* Get name from agent. The string must be freed after using. Returns NULL on error. */
char* wdb_agent_name(int id) {
    char *output = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_name = NULL;

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_SELECT_AGENT], id);    
    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to get the agent name.");
        return NULL;
    }

    json_name = cJSON_GetObjectItemCaseSensitive(root->child,"name");
    if (cJSON_IsString(json_name) && json_name->valuestring != NULL) {
        os_strdup(json_name->valuestring, output);
    }

    cJSON_Delete(root);
    return output;
}

/* Get group from agent. The string must be freed after using. Returns NULL on error. */
char* wdb_agent_group(int id) {
    char *output = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_group = NULL;

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_SELECT_AGENT_GROUP], id);
    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to get the agent group name.");
        return NULL;
    }

    json_group = cJSON_GetObjectItemCaseSensitive(root->child,"name");
    if (cJSON_IsString(json_group) && json_group->valuestring != NULL) {
        os_strdup(json_group->valuestring, output);
    }

    cJSON_Delete(root);
    return output;
}

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
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

/* Remove database for agent. Returns 0 on success or -1 on error. */
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
        return 0;
    } else
        return -1;
}

/* Get an array containing the ID of every agent (except 0), ended with -1 */
int* wdb_get_all_agents() {
    int n = 0;
    int *array = NULL;
    cJSON *json_id = NULL;
    cJSON *root = NULL;
    cJSON *item = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery,"%s", global_db_queries[SQL_SELECT_AGENTS]);
    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to get all agents.");
        return NULL;
    }

    item = root->child;
    os_calloc(cJSON_GetArraySize(root) + 1, sizeof(int), array);

    while (item)
    {
        json_id = cJSON_GetObjectItemCaseSensitive(item,"id");
        
        if(cJSON_IsNumber(json_id)){
            array[n] = json_id->valueint;
            n++;
        }

        item=item->next;
    }

    array[n] = -1;
    cJSON_Delete(root);

    return array;
}

/* Find agent by name and address. Returns id if success, -1 on failure */
int wdb_find_agent(const char *name, const char *ip) {
    int output = -1;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_id = NULL;

    if (!name || !ip) {
        mdebug1("Empty agent name or ip when trying to get agent name. Agent: (%s) IP: (%s)", name, ip);
        return OS_INVALID;
    }

    snprintf(wdbquery, sizeof(wdbquery), global_db_queries[SQL_FIND_AGENT], name, ip, ip);
    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB for agent name.");
        return OS_INVALID;
    }

    json_id = cJSON_GetObjectItemCaseSensitive(root->child,"id");
    if (cJSON_IsNumber(json_id)) {
        output = json_id->valueint;
    }

    cJSON_Delete(root);
    return output;
}

/* Get the file offset. Returns -1 on error. */
long wdb_get_agent_offset(int id_agent, int type) {
    long int output = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_offset = NULL;
    char * column = NULL;

    switch (type) {
    case WDB_SYSCHECK:
        sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_SELECT_FIM_OFFSET], id_agent);
        column = "fim_offset";
        break;
    case WDB_SYSCHECK_REGISTRY:
        sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_SELECT_REG_OFFSET],id_agent);
        column = "reg_offset";
        break;
    default:
        return OS_INVALID;
    }

    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));
    if (!root) {
        merror("Error querying Wazuh DB to get agent offset.");
        return OS_INVALID;
    }

    json_offset = cJSON_GetObjectItemCaseSensitive(root->child,column);
    output = cJSON_IsNumber(json_offset) ? json_offset->valueint : OS_INVALID;

    cJSON_Delete(root);
    return output;
}

/* Set the file offset. Returns 1, or -1 on failure. */
int wdb_set_agent_offset(int id_agent, int type, long offset) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    switch (type) {
    case WDB_SYSCHECK:
        sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_UPDATE_FIM_OFFSET], offset, id_agent);
        break;
    case WDB_SYSCHECK_REGISTRY:
        sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_UPDATE_REG_OFFSET], offset, id_agent);
        break;
    default:
        return OS_INVALID;
    }

    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            result = 1;
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

/* Set agent updating status. Returns WDB_AGENT_*, or OS_INVALID on error. */
int wdb_get_agent_status(int id_agent) {
    int output = -1;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_status = NULL;

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_SELECT_AGENT_STATUS], id_agent);
    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to get the agent status.");
        return OS_INVALID;
    }

    json_status = cJSON_GetObjectItemCaseSensitive(root->child,"status");
    if (cJSON_IsString(json_status) && json_status->valuestring != NULL) {
        output = !strcmp(json_status->valuestring, "empty") ? WDB_AGENT_EMPTY : !strcmp(json_status->valuestring, "pending") ? WDB_AGENT_PENDING : WDB_AGENT_UPDATED;
    } else {
        output = OS_INVALID;
    }

    cJSON_Delete(root);
    return output;
}

/* Set agent updating status. Returns 1, or -1 on error. */
int wdb_set_agent_status(int id_agent, int status) {
    int result = 0;
    const char *str_status = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

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

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_UPDATE_AGENT_STATUS], str_status, id_agent);
    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            result = 1;
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

/* Update agent group. It opens and closes the DB. Returns 1 or -1 on error. */
int wdb_update_agent_group(int id, char *group) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_UPDATE_AGENT_GROUP], group, id);
    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            if (wdb_update_agent_multi_group(id,group) < 0) {
                return OS_INVALID;
            }
            result = 1;
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

/* Update agent multi group. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_multi_group(int id, char *group) {
    int result = 0;

    /* Wipe out the agent multi groups relation for this agent */
    if (wdb_delete_agent_belongs(id) < 0) {
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
                int id_group = wdb_find_group(multi_group);

                if(id_group <= 0) {
                    id_group = wdb_insert_group(multi_group);
                }

                if (wdb_update_agent_belongs(id_group,id) < 0) {
                    return -1;
                }

                multi_group = strtok_r(NULL, delim, &save_ptr);
            }
        } else {
            /* Update de groups table */
            int id_group = wdb_find_group(group);

            if (id_group <= 0) {
                id_group = wdb_insert_group(group);
            }

            if ( wdb_update_agent_belongs(id_group,id) < 0) {
                return OS_INVALID;
            }
        }
    }

    return result;
}

/* Find group by name. Returns id if success or -1 on failure. */
int wdb_find_group(const char *name) {
    int output = -1;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    cJSON *root = NULL;
    cJSON *json_group = NULL;

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_FIND_GROUP], name);
    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to get the agent group id.");
        return OS_INVALID;
    }

    json_group = cJSON_GetObjectItemCaseSensitive(root->child,"id");
    output = cJSON_IsNumber(json_group) ? json_group->valueint : OS_INVALID;

    cJSON_Delete(root);
    return output;
}

/* Insert a new group. Returns id if success or -1 on failure. */
int wdb_insert_group(const char *name) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_INSERT_AGENT_GROUP], name);
    result = wdbc_query_ex( &wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            result = wdb_find_group(name);
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

/* Update agent belongs table. It opens and closes the DB. Returns 1 or -1 on error. */
int wdb_update_agent_belongs(int id_group, int id_agent) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_INSERT_AGENT_BELONG], id_group, id_agent);
    result = wdbc_query_ex( &wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            result = 1;
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

/* Delete agent belongs table. It opens and closes the DB. Returns 1 or -1 on error. */
int wdb_delete_agent_belongs(int id_agent) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_DELETE_AGENT_BELONG], id_agent);
    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            result = 1;
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

int wdb_update_groups(const char *dirname) {
    int result = 0;
    int n = 0;
    int i = 0;
    char **array = NULL;
    cJSON *json_name = NULL;
    cJSON *item = NULL;
    cJSON *root = NULL;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery,"%s", global_db_queries[SQL_SELECT_GROUPS]);
    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to update groups.");
        return OS_INVALID;
    }

    item = root->child;
    os_calloc(cJSON_GetArraySize(root) + 1 , sizeof(char *),array);

    while (item)
    {
        json_name = cJSON_GetObjectItemCaseSensitive(item,"name");
        
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
            if (wdb_remove_group_db((char *)array[i]) < 0) {
                free_strarray(array);
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
        return OS_INVALID;
    }

    while ((dirent = readdir(dir))) {
        if (dirent->d_name[0] != '.') {
            char path[PATH_MAX];
            snprintf(path,PATH_MAX,"%s/%s",dirname,dirent->d_name);

            if (!IsDir(path)) {
                if (wdb_find_group(dirent->d_name) <= 0){
                    wdb_insert_group(dirent->d_name);
                }
            }
        }
    }
    closedir(dir);

    return result;
}

/* Delete group from belongs table. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_group_from_belongs_db(const char *name) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_DELETE_GROUP_BELONG], name);
    result = wdbc_query_ex(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

/* Delete group. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_group_db(const char *name) {
    int result = 0;
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";

    if (wdb_remove_group_from_belongs_db(name) == OS_INVALID) {
        merror("At wdb_remove_group_from_belongs_db(): couldn't delete '%s' from 'belongs' table.", name);
        return OS_INVALID;
    }

    sqlite3_snprintf(sizeof(wdbquery), wdbquery, global_db_queries[SQL_DELETE_GROUP], name);
    result = wdbc_query_ex( &wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    switch (result) {
        case OS_SUCCESS:
            break;
        case OS_INVALID:
            mdebug1("Global DB Error in the response from socket");
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
        default:
            mdebug1("Global DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
            mdebug2("Global DB SQL query: %s", wdbquery);
            return OS_INVALID;
    }

    return result;
}

int wdb_agent_belongs_first_time(){
    int i;
    char *group;
    int *agents;

    if ((agents = wdb_get_all_agents())) {

        for (i = 0; agents[i] != -1; i++) {
            group = wdb_agent_group(agents[i]);

            if (group) {
                wdb_update_agent_multi_group(agents[i],group);
                os_free(group);
            }
        }
        os_free(agents);
    }

    return 0;
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

/* Gets the agent last keepalive. Returns this value, 0 on NULL or OS_INVALID on error */
time_t wdb_get_agent_keepalive (const char *name, const char *ip){
    char wdbquery[WDBQUERY_SIZE] = "";
    char wdboutput[WDBOUTPUT_SIZE] = "";
    time_t output = 0;
    cJSON *root = NULL;
    cJSON *json_keepalive = NULL;

    if (!name || !ip) {
        mdebug1("Empty agent name or ip when trying to get last keepalive. Agent: (%s) IP: (%s)", name, ip);
        return OS_INVALID;
    }

    snprintf(wdbquery, sizeof(wdbquery), global_db_queries[SQL_SELECT_KEEPALIVE], name, ip, ip);
    root = wdbc_query_parse_json(&wdb_sock_agent, wdbquery, wdboutput, sizeof(wdboutput));

    if (!root) {
        merror("Error querying Wazuh DB to get the last agent keepalive.");
        return OS_INVALID;
    }

    json_keepalive = cJSON_GetObjectItemCaseSensitive(root->child,"last_keepalive");
    output = cJSON_IsNumber(json_keepalive) ? json_keepalive->valueint : 0;

    cJSON_Delete(root);
    return output;
}

