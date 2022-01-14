/*
 * Wazuh SQLite integration
 * Copyright (C) 2015, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"

// List of agent information fields in global DB
// The ":" is used for parameter binding
static const char *global_db_agent_fields[] = {
    ":config_sum",
    ":ip",
    ":manager_host",
    ":merged_sum",
    ":name",
    ":node_name",
    ":os_arch",
    ":os_build",
    ":os_codename",
    ":os_major",
    ":os_minor",
    ":os_name",
    ":os_platform",
    ":os_uname",
    ":os_version",
    ":version",
    ":last_keepalive",
    ":connection_status",
    ":disconnection_time",
    ":id",
    NULL
};

static const char *SQL_VACUUM_INTO = "VACUUM INTO ?;";

int wdb_global_insert_agent(wdb_t *wdb, int id, char* name, char* ip, char* register_ip, char* internal_key, char* group, int date_add) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_INSERT_AGENT) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_INSERT_AGENT];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 3, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 4, register_ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 5, internal_key, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 6, date_add) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 7, group, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_update_agent_name(wdb_t *wdb, int id, char* name) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_NAME) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_NAME];

    if (sqlite3_bind_text(stmt, 1, name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 2, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_update_agent_version(wdb_t *wdb,
                                    int id,
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
                                    const char *connection_status,
                                    const char *sync_status)
{
    sqlite3_stmt *stmt = NULL;
    int index = 1;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, agent_ip ? WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP : WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[agent_ip ? WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION_IP : WDB_STMT_GLOBAL_UPDATE_AGENT_VERSION];

    if (sqlite3_bind_text(stmt, index++, os_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_version, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_major, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_minor, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_codename, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_platform, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_build, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_uname, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, os_arch, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, version, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, config_sum, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, merged_sum, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, manager_host, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, node_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (agent_ip) {
        if (sqlite3_bind_text(stmt, index++, agent_ip, -1, NULL) != SQLITE_OK) {
            merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            return OS_INVALID;
        }
    }
    if (sqlite3_bind_text(stmt, index++, connection_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, index++, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, index++, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_get_agent_labels(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_LABELS_GET) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_LABELS_GET];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_del_agent_labels(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_LABELS_DEL) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_LABELS_DEL];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_set_agent_label(wdb_t *wdb, int id, char* key, char* value) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_LABELS_SET) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_LABELS_SET];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, key, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 3, value, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_update_agent_keepalive(wdb_t *wdb, int id, const char *connection_status, const char* sync_status) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_KEEPALIVE];

    if (sqlite3_bind_text(stmt, 1, connection_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 3, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_update_agent_connection_status(wdb_t *wdb, int id, const char *connection_status, const char *sync_status) {
    sqlite3_stmt *stmt = NULL;
    time_t disconnection_time = 0;

    if (!strcmp(connection_status, AGENT_CS_DISCONNECTED)) {
        disconnection_time = time(NULL);
    }

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_CONNECTION_STATUS) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_CONNECTION_STATUS];

    if (sqlite3_bind_text(stmt, 1, connection_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_text(stmt, 2, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 3, disconnection_time) != SQLITE_OK) {
            merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 4, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_delete_agent(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_DELETE_AGENT) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_DELETE_AGENT];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_select_agent_name(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_AGENT_NAME) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_AGENT_NAME];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

cJSON* wdb_global_select_agent_group(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GROUP_CSV_GET) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_GROUP_CSV_GET];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

cJSON* wdb_global_find_agent(wdb_t *wdb, const char *name, const char *ip) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_FIND_AGENT) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_FIND_AGENT];

    if (sqlite3_bind_text(stmt, 1, name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 2, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 3, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_update_agent_group(wdb_t *wdb, int id, char *group) {
    int result = OS_SUCCESS;
    sqlite3_stmt *stmt = NULL;
    char* individual_group = NULL;
    char* temp_group = NULL;
    char* initial_temp = NULL;
    cJSON* j_find_group_result = NULL;
    cJSON* j_group_id = NULL;
    int id_group = -1;
    int group_priority = 0;

    // Making a copy to avoid modifying the original string
    os_strdup(group, temp_group);
    initial_temp = temp_group;

    while (result == OS_SUCCESS && temp_group && (individual_group = strtok_r(temp_group, ",", &temp_group))) {
        j_find_group_result = wdb_global_find_group(wdb, individual_group);
        j_group_id = cJSON_GetObjectItem(j_find_group_result->child, "id");
        id_group = cJSON_IsNumber(j_group_id) ? j_group_id->valueint : OS_INVALID;
        cJSON_Delete(j_find_group_result);
        // Updating belongs table, an invalid group will be rejected by the FOREIGN KEY constraint
        result = wdb_global_insert_agent_belong(wdb, id_group, id, group_priority);
        group_priority++;
    }

    os_free(initial_temp);
    if(result == OS_INVALID) {
        return result;
    }

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_GROUP];

    if (sqlite3_bind_text(stmt, 1, group, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 2, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        result = OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        result = OS_INVALID;
    }

    return result;
}

int wdb_global_update_agent_groups_hash(wdb_t* wdb, int agent_id, char* groups_string) {
    int result = OS_INVALID;
    char groups_hash[WDB_GROUP_HASH_SIZE+1] = {0};

    // If the comma-separated groups string is not sent, read it from 'group' column
    if (groups_string) {
        OS_SHA256_String_sized(groups_string, groups_hash, WDB_GROUP_HASH_SIZE);
    }
    else {
        char* agent_group_csv = wdb_global_get_agent_group_csv(wdb, agent_id);
        if (agent_group_csv) {
            OS_SHA256_String_sized(agent_group_csv, groups_hash, WDB_GROUP_HASH_SIZE);
            os_free(agent_group_csv);
        }
        else {
            mdebug2("Empty group column for agent '%d'. The groups_hash column won't be updated", agent_id);
            return OS_SUCCESS;
        }
	}

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_GROUPS_HASH) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_GROUPS_HASH];
    if (sqlite3_bind_text(stmt, 1, groups_hash, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (sqlite3_bind_int(stmt, 2, agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_DONE:
        result = OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        result = OS_INVALID;
    }

    return result;
}

int wdb_global_update_all_agents_groups_hash(wdb_t* wdb) {
    int step_result = -1;
    int update_result = OS_SUCCESS;
    int result = OS_INVALID;
    int agent_id = -1;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS];

    if (sqlite3_bind_int(stmt, 1, 0) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    do {
        step_result = wdb_step(stmt);
        switch (step_result) {
        case SQLITE_ROW:
            agent_id = sqlite3_column_int(stmt, 0);
            update_result = wdb_global_update_agent_groups_hash(wdb, agent_id, NULL);
            break;
        case SQLITE_DONE:
            result = OS_SUCCESS;
            break;
        default:
            mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
            result = OS_INVALID;
        }
    } while(step_result == SQLITE_ROW && update_result == OS_SUCCESS);

    return result;
}

cJSON* wdb_global_find_group(wdb_t *wdb, char* group_name) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_FIND_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_FIND_GROUP];

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_insert_agent_group(wdb_t *wdb, char* group_name) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_INSERT_AGENT_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_INSERT_AGENT_GROUP];

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_select_group_belong(wdb_t *wdb, int id_agent) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_GROUP_BELONG) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_GROUP_BELONG];

    if (sqlite3_bind_int(stmt, 1, id_agent) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt_single_column(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_insert_agent_belong(wdb_t *wdb, int id_group, int id_agent, int priority) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_INSERT_AGENT_BELONG) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_INSERT_AGENT_BELONG];

    if (sqlite3_bind_int(stmt, 1, id_group) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 2, id_agent) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 3, priority) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_delete_group_belong(wdb_t *wdb, char* group_name) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_DELETE_GROUP_BELONG) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_DELETE_GROUP_BELONG];

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_delete_group(wdb_t *wdb, char* group_name) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_DELETE_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_DELETE_GROUP];

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_select_groups(wdb_t *wdb) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_GROUPS) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_GROUPS];

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

cJSON* wdb_global_select_agent_keepalive(wdb_t *wdb, char* name, char* ip) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_AGENT_KEEPALIVE) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_AGENT_KEEPALIVE];

    if (sqlite3_bind_text(stmt, 1, name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 2, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 3, ip, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

int wdb_global_delete_agent_belong(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_DELETE_AGENT_BELONG) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_DELETE_AGENT_BELONG];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

int wdb_global_set_sync_status(wdb_t *wdb, int id, const char* sync_status) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SYNC_SET) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SYNC_SET];

    if (sqlite3_bind_text(stmt, 1, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 2, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

wdbc_result wdb_global_sync_agent_info_get(wdb_t *wdb, int* last_agent_id, char **output) {
    sqlite3_stmt* agent_stmt = NULL;
    unsigned response_size = 2;     //Starts with "[]" size
    wdbc_result status = WDBC_UNKNOWN;

    os_calloc(WDB_MAX_RESPONSE_SIZE, sizeof(char), *output);
    char *response_aux = *output;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", "Cannot begin transaction");
        return WDBC_ERROR;
    }

    //Add array start
    *response_aux++ = '[';

    while (status == WDBC_UNKNOWN) {
        //Prepare SQL query
        if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SYNC_REQ_GET) < 0) {
            mdebug1("Cannot cache statement");
            snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", "Cannot cache statement");
            status = WDBC_ERROR;
            break;
        }
        agent_stmt = wdb->stmt[WDB_STMT_GLOBAL_SYNC_REQ_GET];
        if (sqlite3_bind_int(agent_stmt, 1, *last_agent_id) != SQLITE_OK) {
            merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", "Cannot bind sql statement");
            status = WDBC_ERROR;
            break;
        }

        //Get agent info
        cJSON* sql_agents_response = wdb_exec_stmt(agent_stmt);
        if (sql_agents_response && sql_agents_response->child) {
            cJSON* json_agent = sql_agents_response->child;
            cJSON* json_id = cJSON_GetObjectItem(json_agent,"id");
            if (cJSON_IsNumber(json_id)) {
                //Get ID
                int agent_id = json_id->valueint;

                //Get labels if any
                cJSON* json_labels = wdb_global_get_agent_labels(wdb, agent_id);
                if (json_labels) {
                    if (json_labels->child) {
                        cJSON_AddItemToObject(json_agent, "labels", json_labels);
                    }
                    else {
                        cJSON_Delete(json_labels);
                    }
                }

                //Print Agent info
                char *agent_str = cJSON_PrintUnformatted(json_agent);
                unsigned agent_len = strlen(agent_str);

                //Check if new agent fits in response
                if (response_size+agent_len+1 < WDB_MAX_RESPONSE_SIZE) {
                    //Add new agent
                    memcpy(response_aux, agent_str, agent_len);
                    response_aux+=agent_len;
                    //Add separator
                    *response_aux++ = ',';
                    //Save size and last ID
                    response_size += agent_len+1;
                    *last_agent_id = agent_id;
                    //Set sync status as synced
                    if (OS_SUCCESS != wdb_global_set_sync_status(wdb, agent_id, "synced")) {
                        merror("Cannot set sync_status for agent %d", agent_id);
                        snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s %d", "Cannot set sync_status for agent", agent_id);
                        status = WDBC_ERROR;
                    }
                }
                else {
                    //Pending agents but buffer is full
                    status = WDBC_DUE;
                }
                os_free(agent_str);
            }
            else {
                //Continue with the next agent
                (*last_agent_id)++;
            }
        }
        else {
            //All agents have been obtained
            status = WDBC_OK;
        }
        cJSON_Delete(sql_agents_response);
    }

    if (status != WDBC_ERROR) {
        if (response_size > 2) {
            //Remove last ','
            response_aux--;
        }
        //Add array end
        *response_aux = ']';
    }
    return status;
}

char* wdb_global_calculate_agent_group_csv(wdb_t *wdb, int id) {
    cJSON* j_agent_groups = wdb_global_select_group_belong(wdb, id);
    char* result = NULL;
    if (j_agent_groups) {
        cJSON* j_group_name = NULL;
        cJSON_ArrayForEach(j_group_name, j_agent_groups) {
            wm_strcat(&result, cJSON_GetStringValue(j_group_name), MULTIGROUP_SEPARATOR);
        }
        cJSON_Delete(j_agent_groups);
    }
    else {
        mdebug1("Unable to get groups of agent '%d'", id);
    }
    return result;
}


char* wdb_global_get_agent_group_csv(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_CSV_GET);

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    char* group_csv = NULL;
    cJSON* j_result = wdb_exec_stmt(stmt);
    if (j_result) {
        group_csv = cJSON_GetStringValue(cJSON_GetObjectItem(j_result->child, "group"));
        if (group_csv) {
            // Detaching the string from the json structure
            os_strdup(group_csv,group_csv);
        }
        cJSON_Delete(j_result);
    }
    else{
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return group_csv;
}


wdbc_result wdb_global_set_agent_group_context(wdb_t *wdb, int id, char* csv, char* hash, char* sync_status) {

    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_CTX_SET);
    if (stmt == NULL) {
        return WDBC_ERROR;
    }

    sqlite3_bind_text(stmt, 1, csv, -1, NULL);
    sqlite3_bind_text(stmt, 2, hash, -1, NULL);
    sqlite3_bind_text(stmt, 3, sync_status, -1, NULL);
    sqlite3_bind_int(stmt, 4, id);

    if (OS_SUCCESS == wdb_exec_stmt_silent(stmt)) {
        return WDBC_OK;
    }
    else {
        mdebug1("Error executing setting the agent group context: %s", sqlite3_errmsg(wdb->db));
        return WDBC_ERROR;
    }
}

cJSON* wdb_get_groups_integrity(wdb_t* wdb, os_sha1 hash) {
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND);

    if (stmt == NULL) {
        return NULL;
    }

    cJSON* response = NULL;

    switch (sqlite3_step(stmt)) {
    case SQLITE_ROW:
        response = cJSON_CreateArray();

        cJSON_AddItemToArray(response, cJSON_CreateString("syncreq"));
        return response;
    case SQLITE_DONE:
        response = cJSON_CreateArray();
        os_sha1 hexdigest = {0};

        if ( OS_SUCCESS == wdb_get_global_group_hash(wdb, hexdigest) && !strcmp(hexdigest, hash)) {
            cJSON_AddItemToArray(response, cJSON_CreateString("synced"));
        } else {
            cJSON_AddItemToArray(response, cJSON_CreateString("hash_mismatch"));
        }
        return response;
    default:
        mdebug1("DB(%s) sqlite3_step(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return response;
    }
}

int wdb_global_get_agent_max_group_priority(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_PRIORITY_GET);

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    int group_priority = OS_INVALID;
    cJSON* j_result = wdb_exec_stmt(stmt);
    if (j_result) {
        if (j_result->child->child) {
            cJSON* j_priority = j_result->child->child;
            group_priority = j_priority->valueint;
        }
        cJSON_Delete(j_result);
    }
    else{
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return group_priority;
}


wdbc_result wdb_global_assign_agent_group(wdb_t *wdb, int id, cJSON* j_groups, int priority) {
    cJSON* j_group_name = NULL;
    wdbc_result result = WDBC_OK;
    cJSON_ArrayForEach (j_group_name, j_groups) {
        if (cJSON_IsString(j_group_name)){
            char* group_name = j_group_name->valuestring;
            if (OS_INVALID == wdb_global_insert_agent_group(wdb, group_name)) {
                result = WDBC_ERROR;
            }

            cJSON* j_find_response = wdb_global_find_group(wdb, group_name);
            cJSON* j_group_id = cJSON_GetObjectItem(j_find_response->child,"id");
            int group_id = j_group_id->valueint;
            cJSON_Delete(j_find_response);
            if (OS_INVALID == wdb_global_insert_agent_belong(wdb, group_id, id, priority)) {
                result = WDBC_ERROR;
            }
            priority++;
        }
        else {
            mdebug1("Invalid groups set information");
            result = WDBC_ERROR;
            continue;
        }
    }
    return result;
}

wdbc_result wdb_global_set_agent_groups(wdb_t *wdb, wdb_groups_set_mode_t mode, char* sync_status, cJSON* j_agents_group_info) {
    wdbc_result ret = WDBC_OK;
    cJSON* j_group_info = NULL;
    cJSON_ArrayForEach (j_group_info, j_agents_group_info) {
        cJSON* j_agent_id = cJSON_GetObjectItem(j_group_info, "id");
        cJSON* j_groups = cJSON_GetObjectItem(j_group_info, "groups");
        if (cJSON_IsNumber(j_agent_id) && cJSON_IsArray(j_groups)) {
            int agent_id = j_agent_id->valueint;
            int group_priority = 0;

            if (mode == WDB_GROUP_OVERRIDE ) {
                if (OS_INVALID == wdb_global_delete_agent_belong(wdb, agent_id)) {
                    ret = WDBC_ERROR;
                    merror("There was an error cleaning the previous agent groups");
                }
            }
            else {
                int last_group_priority = wdb_global_get_agent_max_group_priority(wdb, agent_id);
                if (last_group_priority >= 0) {
                    if (mode == WDB_GROUP_EMPTY_ONLY) {
                        mdebug2("Agent group set in empty_only mode ignored because the agent already contains groups");
                        continue;
                    }
                    group_priority = last_group_priority+1;
                }
            }

            if (WDBC_ERROR == wdb_global_assign_agent_group(wdb, agent_id, j_groups, group_priority)) {
                ret = WDBC_ERROR;
                merror("There was an error assigning the groups to agent '%03d'", agent_id);
            }

            char* agent_groups_csv = wdb_global_calculate_agent_group_csv(wdb, agent_id);
            if (agent_groups_csv) {
                char groups_hash[WDB_GROUP_HASH_SIZE+1] = {0};
                OS_SHA256_String_sized(agent_groups_csv, groups_hash, WDB_GROUP_HASH_SIZE);
                if (WDBC_ERROR == wdb_global_set_agent_group_context(wdb, agent_id, agent_groups_csv, groups_hash, sync_status)) {
                    ret = WDBC_ERROR;
                    merror("There was an error assigning the groups context to agent '%03d'", agent_id);
                }
                os_free(agent_groups_csv);
                wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_CLEAR, NULL);
            }
            else {
                ret = WDBC_ERROR;
                mdebug1("The agent groups where empty right after the set");
            }
        }
        else {
            ret = WDBC_ERROR;
            mdebug1("Invalid groups set information");
            continue;
        }
    }
    return ret;
}

int wdb_global_set_agent_groups_sync_status(wdb_t *wdb, int id, const char* sync_status) {
    sqlite3_stmt *stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_SYNC_SET);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    if (sqlite3_bind_text(stmt, 1, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 2, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}

wdbc_result wdb_global_sync_agent_groups_get(wdb_t *wdb, wdb_groups_sync_condition_t condition, int last_agent_id, bool set_synced, bool get_hash, cJSON** output) {
    wdbc_result status = WDBC_UNKNOWN;

    wdb_stmt sync_statement_index = WDB_STMT_GLOBAL_GROUP_SYNC_REQ_GET;
    switch (condition) {
        case WDB_GROUP_SYNC_STATUS:
            sync_statement_index = WDB_STMT_GLOBAL_GROUP_SYNC_REQ_GET;
            break;
        case WDB_GROUP_ALL:
            sync_statement_index = WDB_STMT_GLOBAL_GROUP_SYNC_ALL_GET;
            break;
        default:
            mdebug1("Invalid groups sync condition");
            return WDBC_ERROR;
    }


    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return WDBC_ERROR;
    }

    *output = cJSON_CreateArray();
    cJSON* j_response = cJSON_CreateObject();
    cJSON* j_data = cJSON_CreateArray();
    cJSON_AddItemToArray(*output, j_response);
    cJSON_AddItemToObject(j_response, "data", j_data);
    char *out_aux = cJSON_PrintUnformatted(*output);
    size_t response_size = strlen(out_aux);
    os_free(out_aux);

    while (status == WDBC_UNKNOWN) {
        //Prepare SQL query
        if (wdb_stmt_cache(wdb, sync_statement_index) < 0) {
            mdebug1("Cannot cache statement");
            status = WDBC_ERROR;
            break;
        }
        sqlite3_stmt* sync_stmt = wdb->stmt[sync_statement_index];
        if (sqlite3_bind_int(sync_stmt, 1, last_agent_id) != SQLITE_OK) {
            merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            status = WDBC_ERROR;
            break;
        }

        //Get agents to sync
        cJSON* j_agent_stmt = wdb_exec_stmt(sync_stmt);
        if (j_agent_stmt && j_agent_stmt->child) {
            cJSON* j_agent = j_agent_stmt->child;
            cJSON* j_id = cJSON_GetObjectItem(j_agent,"id");
            if (cJSON_IsNumber(j_id)) {
                //Get agent ID
                last_agent_id = j_id->valueint;
                //Get the groups of the agent
                cJSON* j_groups = wdb_global_select_group_belong(wdb, last_agent_id);
                if (j_groups) {
                    if (j_groups->child) {
                        cJSON_AddItemToObject(j_agent, "groups", j_groups);
                        //Print Agent groups
                        char *agent_str = cJSON_PrintUnformatted(j_agent);
                        unsigned agent_len = strlen(agent_str);

                        //Check if new agent fits in response
                        if (response_size+agent_len+1 < WDB_MAX_RESPONSE_SIZE) {
                            //Add new agent
                            cJSON_AddItemToArray(j_data, cJSON_Duplicate(j_agent, true));
                            //Save size
                            response_size += agent_len+1;
                        }
                        else {
                            //Pending agents but buffer is full
                            status = WDBC_DUE;
                        }
                        os_free(agent_str);
                    }
                    else {
                        cJSON_Delete(j_groups);
                    }
                }
                if (set_synced) {
                    //Set groups sync status as synced
                    if (OS_SUCCESS != wdb_global_set_agent_groups_sync_status(wdb, last_agent_id, "synced")) {
                        merror("Cannot set group_sync_status for agent %d", last_agent_id);
                        status = WDBC_ERROR;
                    }
                }
            }
            else {
                //Continue with the next agent
                last_agent_id++;
            }
        }
        else {
            //All agents have been obtained
            if (get_hash) {
                size_t hash_len = strlen("hash:\"\"")+sizeof(os_sha1);
                if (response_size+hash_len+1 < WDB_MAX_RESPONSE_SIZE) {
                    os_sha1 hash = "";
                    if (OS_SUCCESS == wdb_get_global_group_hash(wdb, hash)) {
                        cJSON_AddStringToObject(j_response, "hash", hash);
                        status = WDBC_OK;
                    }
                    else {
                        merror("Cannot obtain the global group hash");
                        status = WDBC_ERROR;
                    }
                }
                else {
                    status = WDBC_DUE;
                }
            }
            else {
                status = WDBC_OK;
            }
        }
        cJSON_Delete(j_agent_stmt);
    }

    return status;
}

int wdb_global_sync_agent_info_set(wdb_t *wdb,cJSON * json_agent){
    sqlite3_stmt *stmt = NULL;
    int n = 0;
    int index = 0;
    cJSON *json_field = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_INFO) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_INFO];

    for (n = 0 ; global_db_agent_fields[n] ; n++){
        // Every column name of Global DB is stored in global_db_agent_fields
        json_field = cJSON_GetObjectItem(json_agent, global_db_agent_fields[n]+1);
        index = sqlite3_bind_parameter_index(stmt, global_db_agent_fields[n]);
        if (cJSON_IsNumber(json_field) && index != 0){
            if (sqlite3_bind_int(stmt, index , json_field->valueint) != SQLITE_OK) {
                merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }

        } else if (cJSON_IsString(json_field) && json_field->valuestring != NULL && index != 0) {
            if (sqlite3_bind_text(stmt, index , json_field->valuestring, -1, NULL) != SQLITE_OK) {
                merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                return OS_INVALID;
            }
        }
    }

    index = sqlite3_bind_parameter_index(stmt, ":sync_status");
    if (sqlite3_bind_text(stmt, index, "synced", -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_get_agent_info(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    cJSON * result = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENT_INFO) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENT_INFO];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    result = wdb_exec_stmt(stmt);

    if (!result) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return result;
}

cJSON* wdb_global_get_agents_to_disconnect(wdb_t *wdb, int last_agent_id, int keep_alive, const char *sync_status, wdbc_result* status) {
    sqlite3_stmt* stmt = NULL;

    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        *status = WDBC_ERROR;
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS_TO_DISCONNECT) < 0) {
        mdebug1("Cannot cache statement");
        *status = WDBC_ERROR;
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS_TO_DISCONNECT];

    if (sqlite3_bind_int(stmt, 1, last_agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    if (sqlite3_bind_int(stmt, 2, keep_alive) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    //Execute SQL query limited by size
    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status);
    if (SQLITE_DONE == sql_status) *status = WDBC_OK;
    else if (SQLITE_ROW == sql_status) *status = WDBC_DUE;
    else *status = WDBC_ERROR;

    //Set every obtained agent as 'disconnected'
    cJSON* agent = NULL;
    cJSON_ArrayForEach(agent, result) {
        cJSON* id = cJSON_GetObjectItem(agent, "id");
        if (cJSON_IsNumber(id)) {
            //Set connection status as disconnected
            if (OS_SUCCESS != wdb_global_update_agent_connection_status(wdb, id->valueint, "disconnected", sync_status)) {
                merror("Cannot set connection_status for agent %d", id->valueint);
                *status = WDBC_ERROR;
            }
        }
        else {
            merror("Invalid element returned by disconnect query");
            *status = WDBC_ERROR;
        }
    }

    return result;
}

cJSON* wdb_global_get_all_agents(wdb_t *wdb, int last_agent_id, wdbc_result* status) {
    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        *status = WDBC_ERROR;
        return NULL;
    }
    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS) < 0) {
        mdebug1("Cannot cache statement");
        *status = WDBC_ERROR;
        return NULL;
    }
    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS];
    if (sqlite3_bind_int(stmt, 1, last_agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    //Execute SQL query limited by size
    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status);
    if (SQLITE_DONE == sql_status) *status = WDBC_OK;
    else if (SQLITE_ROW == sql_status) *status = WDBC_DUE;
    else *status = WDBC_ERROR;

    return result;
}

int wdb_global_agent_exists(wdb_t *wdb, int agent_id) {
    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }
    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_AGENT_EXISTS) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }
    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_AGENT_EXISTS];
    if (sqlite3_bind_int(stmt, 1, agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }


    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        return sqlite3_column_int(stmt, 0);
    case SQLITE_DONE:
        return 0;
    default:
        return OS_INVALID;
    }
}

int wdb_global_reset_agents_connection(wdb_t *wdb, const char *sync_status) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_RESET_CONNECTION_STATUS) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_RESET_CONNECTION_STATUS];

    if (sqlite3_bind_text(stmt, 1, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
    case SQLITE_DONE:
        return OS_SUCCESS;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
}

cJSON* wdb_global_get_agents_by_connection_status (wdb_t *wdb, int last_agent_id, const char* connection_status, wdbc_result* status) {
    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        *status = WDBC_ERROR;
        return NULL;
    }
    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS) < 0) {
        mdebug1("Cannot cache statement");
        *status = WDBC_ERROR;
        return NULL;
    }
    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS];
    if (sqlite3_bind_int(stmt, 1, last_agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }
    if (sqlite3_bind_text(stmt, 2, connection_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    //Execute SQL query limited by size
    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status);
    if (SQLITE_DONE == sql_status) *status = WDBC_OK;
    else if (SQLITE_ROW == sql_status) *status = WDBC_DUE;
    else *status = WDBC_ERROR;

    return result;
}

int wdb_global_create_backup(wdb_t* wdb, char* output, const char* tag) {
    char path[PATH_MAX-3] = {0};
    char path_compressed[PATH_MAX] = {0};
    int result = OS_INVALID;
    char* timestamp = NULL;

    timestamp = w_get_timestamp(time(NULL));
    wchr_replace(timestamp, ' ', '-');
    wchr_replace(timestamp, '/', '-');
    snprintf(path, PATH_MAX-3, "%s/%s-%s%s", WDB_BACKUP_FOLDER, WDB_GLOB_BACKUP_NAME, timestamp, tag ? tag : "");
    os_free(timestamp);

    // Commiting pending transaction to run VACUUM
    if (wdb_commit2(wdb) == OS_INVALID) {
        mdebug1("Cannot commit current transaction to create backup");
        snprintf(output, OS_MAXSTR + 1, "err Cannot commit current transaction to create backup");
        return OS_INVALID;
    }

    // Clear all statements in cache to run VACUUM
    wdb_finalize_all_statements(wdb);

    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(wdb->db, SQL_VACUUM_INTO, -1, &stmt, NULL) != SQLITE_OK) {
        mdebug1("sqlite3_prepare_v2(): %s", sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (sqlite3_bind_text(stmt, 1, path , -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        snprintf(output, OS_MAXSTR + 1, "err DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        sqlite3_finalize(stmt);
        return OS_INVALID;
    }

    result = wdb_exec_stmt_silent(stmt);
    if (OS_INVALID == result) {
        snprintf(output, OS_MAXSTR + 1, "err SQLite: %s", sqlite3_errmsg(wdb->db));
    }

    sqlite3_finalize(stmt);

    if (OS_SUCCESS == result) {
        snprintf(path_compressed, PATH_MAX, "%s.gz", path);
        result = w_compress_gzfile(path, path_compressed);
        unlink(path);
        if(OS_SUCCESS == result) {
            minfo("Created Global database backup \"%s\"", path);
            wdb_global_remove_old_backups();
            cJSON* j_path = cJSON_CreateArray();
            cJSON_AddItemToArray(j_path, cJSON_CreateString(path));
            char* output_str = cJSON_PrintUnformatted(j_path);
            snprintf(output, OS_MAXSTR + 1, "ok %s", output_str);
            cJSON_Delete(j_path);
            os_free(output_str);
        } else {
            snprintf(output, OS_MAXSTR + 1, "err Failed during database backup compression");
        }
    }

    return result;
}

int wdb_global_remove_old_backups() {
    DIR* dp = opendir(WDB_BACKUP_FOLDER);

    if(!dp) {
        mdebug1("Unable to open backup directory '%s'", WDB_BACKUP_FOLDER);
        return OS_INVALID;
    }

    int number_of_files = 0;
    struct dirent *entry = NULL;

    while (entry = readdir(dp), entry) {
        if (strncmp(entry->d_name, WDB_GLOB_BACKUP_NAME, sizeof(WDB_GLOB_BACKUP_NAME) - 1) != 0) {
            continue;
        }

        number_of_files++;
    }
    closedir(dp);

    int backups_to_delete = number_of_files - wconfig.wdb_backup_settings[WDB_GLOBAL_BACKUP]->max_files;
    char tmp_path[OS_SIZE_512] = {0};

    for (int i = 0; backups_to_delete > i; i++) {
        char* backup_to_delete_name = NULL;
        wdb_global_get_oldest_backup(&backup_to_delete_name);
        if (backup_to_delete_name) {
            snprintf(tmp_path, OS_SIZE_512, "%s/%s", WDB_BACKUP_FOLDER, backup_to_delete_name);
            unlink(tmp_path);
            minfo("Deleted Global database backup: \"%s\"", tmp_path);
            os_free(backup_to_delete_name);
        }
    }

    return OS_SUCCESS;
}

cJSON* wdb_global_get_backups() {
    cJSON* j_backups = NULL;
    struct dirent *entry = NULL;

    DIR* dp = opendir(WDB_BACKUP_FOLDER);

    if(!dp) {
        mdebug1("Unable to open backup directory '%s'", WDB_BACKUP_FOLDER);
        return NULL;
    }

    j_backups = cJSON_CreateArray();
    while (entry = readdir(dp), entry) {
        if (strncmp(entry->d_name, WDB_GLOB_BACKUP_NAME, sizeof(WDB_GLOB_BACKUP_NAME) - 1) != 0) {
            continue;
        }

        cJSON_AddItemToArray(j_backups, cJSON_CreateString(entry->d_name));
    }

    closedir(dp);
    return j_backups;
}

int wdb_global_restore_backup(wdb_t** wdb, char* snapshot, bool save_pre_restore_state, char* output) {
    char* backup_to_restore = NULL;

    // If the snapshot is not present, the most recent backup will be used
    if (snapshot) {
        backup_to_restore = snapshot;
    } else {
        wdb_global_get_most_recent_backup(&backup_to_restore);
    }

    char global_path[OS_SIZE_256] = {0};

    snprintf(global_path, OS_SIZE_256, "%s/%s.db", WDB2_DIR, WDB_GLOB_NAME);

    int result = OS_INVALID;
    if (save_pre_restore_state) {
        if (OS_SUCCESS != wdb_global_create_backup(*wdb, output, "-pre_restore")) {
            merror("Creating pre-restore Global DB snapshot failed. Backup restore stopped: %s", output);
            goto end;
        }
    }

    if (backup_to_restore) {
        char global_tmp_path[OS_SIZE_256] = {0};
        char backup_to_restore_path[OS_SIZE_256] = {0};

        snprintf(global_tmp_path, OS_SIZE_256, "%s/%s.db.back", WDB2_DIR, WDB_GLOB_NAME);
        snprintf(backup_to_restore_path, OS_SIZE_256, "%s/%s", WDB_BACKUP_FOLDER, backup_to_restore);

        if (!w_uncompress_gzfile(backup_to_restore_path, global_tmp_path)) {
            // Preparing DB for restoration.
            wdb_leave(*wdb);
            wdb_close(*wdb, true);
            *wdb = NULL;

            unlink(global_path);
            rename(global_tmp_path, global_path);
            snprintf(output, OS_MAXSTR + 1, "ok");
            result = OS_SUCCESS;
        } else {
            mdebug1("Failed during backup decompression");
            snprintf(output, OS_MAXSTR + 1, "err Failed during backup decompression");
            result = OS_INVALID;
        }
    } else {
        mdebug1("Unable to found a snapshot to restore");
        snprintf(output, OS_MAXSTR + 1, "err Unable to found a snapshot to restore");
        result = OS_INVALID;
    }

end:
    if (!snapshot) {
        os_free(backup_to_restore);
    }
    return result;
}

time_t wdb_global_get_most_recent_backup(char **most_recent_backup_name) {
    DIR* dp = opendir(WDB_BACKUP_FOLDER);

    if(!dp) {
        mdebug1("Unable to open backup directory '%s'", WDB_BACKUP_FOLDER);
        return OS_INVALID;
    }

    struct dirent *entry = NULL;
    char *tmp_backup_name = NULL;
    time_t most_recent_backup_time = OS_INVALID;

    while (entry = readdir(dp), entry) {
        if (strncmp(entry->d_name, WDB_GLOB_BACKUP_NAME, sizeof(WDB_GLOB_BACKUP_NAME) - 1) != 0) {
            continue;
        }
        char tmp_path[OS_SIZE_512] = {0};
        struct stat backup_info = {0};

        snprintf(tmp_path, OS_SIZE_512, "%s/%s", WDB_BACKUP_FOLDER, entry->d_name);
        if(!stat(tmp_path, &backup_info) ) {
            if(backup_info.st_mtime >= most_recent_backup_time) {
                most_recent_backup_time = backup_info.st_mtime;
                tmp_backup_name = entry->d_name;
            }
        }
    }

    closedir(dp);
    if(most_recent_backup_name && tmp_backup_name) {
        os_strdup(tmp_backup_name, *most_recent_backup_name);
    }

    return most_recent_backup_time;
}

time_t wdb_global_get_oldest_backup(char **oldest_backup_name) {
    DIR* dp = opendir(WDB_BACKUP_FOLDER);

    if(!dp) {
        mdebug1("Unable to open backup directory '%s'", WDB_BACKUP_FOLDER);
        return OS_INVALID;
    }

    struct dirent *entry = NULL;
    time_t oldest_backup_time = OS_INVALID;
    time_t current_time = time(NULL);
    char *tmp_backup_name = NULL;

    while (entry = readdir(dp), entry) {
        if (strncmp(entry->d_name, WDB_GLOB_BACKUP_NAME, sizeof(WDB_GLOB_BACKUP_NAME) - 1) != 0) {
            continue;
        }
        char tmp_path[OS_SIZE_512] = {0};
        struct stat backup_info = {0};

        snprintf(tmp_path, OS_SIZE_512, "%s/%s", WDB_BACKUP_FOLDER, entry->d_name);
        if(!stat(tmp_path, &backup_info) ) {
            if((current_time - backup_info.st_mtime) >= oldest_backup_time) {
                oldest_backup_time = current_time - backup_info.st_mtime;
                tmp_backup_name = entry->d_name;
            }
        }
    }

    closedir(dp);
    if(oldest_backup_name && tmp_backup_name) {
        os_strdup(tmp_backup_name, *oldest_backup_name);
    }

    return oldest_backup_time;
}

sqlite3_stmt * wdb_get_cache_stmt(wdb_t * wdb, char const *query) {
    sqlite3_stmt * ret_val = NULL;
    if (NULL != wdb && NULL != query) {
        struct stmt_cache_list *node_stmt = NULL;
        for (node_stmt = wdb->cache_list; node_stmt ; node_stmt=node_stmt->next) {
            if (node_stmt->value.query) {
                if (strcmp(node_stmt->value.query, query) == 0)
                {
                    if (sqlite3_reset(node_stmt->value.stmt) != SQLITE_OK || sqlite3_clear_bindings(node_stmt->value.stmt) != SQLITE_OK) {
                        mdebug1("DB(%s) sqlite3_reset() stmt(%s): %s", wdb->id, sqlite3_sql(node_stmt->value.stmt), sqlite3_errmsg(wdb->db));
                    }
                    ret_val = node_stmt->value.stmt;
                    break;
                }
            }
        }
        bool is_first_element = true;
        if (NULL == ret_val) {
            struct stmt_cache_list *new_item = NULL;
            if (NULL == wdb->cache_list) {
                os_malloc(sizeof(struct stmt_cache_list), wdb->cache_list);
                new_item = wdb->cache_list;
            } else {
                node_stmt = wdb->cache_list;
                while (node_stmt->next){
                    node_stmt = node_stmt->next;
                }
                is_first_element = false;
                os_malloc(sizeof(struct stmt_cache_list), node_stmt->next);
                //Add element in the end list
                new_item = node_stmt->next;
            }
            new_item->next = NULL;
            os_malloc(strlen(query) + 1, new_item->value.query);
            strcpy(new_item->value.query, query);

            if (sqlite3_prepare_v2(wdb->db, new_item->value.query, -1, &new_item->value.stmt, NULL) != SQLITE_OK) {
                merror("DB(%s) sqlite3_prepare_v2() : %s", wdb->id, sqlite3_errmsg(wdb->db));
                os_free(new_item->value.query);
                if (is_first_element) {
                    os_free(wdb->cache_list);
                    wdb->cache_list = NULL;
                } else {
                    os_free(node_stmt->next);
                    node_stmt->next = NULL;
                }
            } else {
                ret_val = new_item->value.stmt;
            }
        }
    }
    return ret_val;
}

bool wdb_single_row_insert_dbsync(wdb_t * wdb, struct kv const *kv_value, char *data) {
    bool ret_val = false;
    if (NULL != kv_value) {
        char query[OS_SIZE_2048] = { 0 };
        strcat(query, "DELETE FROM ");
        strcat(query, kv_value->value);
        strcat(query, ";");
        sqlite3_stmt *stmt = wdb_get_cache_stmt(wdb, query);

        if (NULL != stmt) {
            ret_val = SQLITE_DONE == wdb_step(stmt) ? true : false;
        } else {
            mdebug1("Cannot get cache statement");
        }
        ret_val = ret_val && wdb_insert_dbsync(wdb, kv_value, data);
    }

    return ret_val;
}

bool wdb_insert_dbsync(wdb_t * wdb, struct kv const *kv_value, char *data) {
    bool ret_val = false;

    if (NULL != data && NULL != wdb && NULL != kv_value) {
        char query[OS_SIZE_2048] = { 0 };
        strcat(query, "INSERT INTO ");
        strcat(query, kv_value->value);
        strcat(query, " VALUES (");
        struct column_list const *column = NULL;

        for (column = kv_value->column_list; column ; column=column->next) {
            strcat(query, "?");
            if (column->next) {
                strcat(query, ",");
            }
        }
        strcat(query, ");");

        sqlite3_stmt *stmt = wdb_get_cache_stmt(wdb, query);

        if (NULL != stmt) {
            char *field_value = strtok(data, FIELD_SEPARATOR_DBSYNC);
            for (column = kv_value->column_list; column ; column=column->next) {
                if (column->value.is_old_implementation) {
                    if (FIELD_TEXT == column->value.type) {
                        if (SQLITE_OK != sqlite3_bind_text(stmt, column->value.index, "", -1, NULL)) {
                            merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                        }
                    } else {
                        if (SQLITE_OK != sqlite3_bind_int(stmt, column->value.index, 0)) {
                            merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                        }
                    }
                } else {
                    if (NULL != field_value) {
                        if (FIELD_TEXT == column->value.type) {
                            if (SQLITE_OK != sqlite3_bind_text(stmt, column->value.index, strcmp(field_value, "NULL") == 0 ? "" : field_value, -1, NULL)) {
                                merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                            }
                        } else {
                            if (SQLITE_OK != sqlite3_bind_int(stmt, column->value.index, strcmp(field_value, "NULL") == 0 ? 0 : atoi(field_value))) {
                                merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                            }
                        }
                        if (column->next) {
                            field_value = strtok(NULL, FIELD_SEPARATOR_DBSYNC);
                        }
                    }
                }
            }
            ret_val = SQLITE_DONE == wdb_step(stmt);
        } else {
            mdebug1("Cannot get cache statement");
        }
    }
    return ret_val;
}

bool wdb_modify_dbsync(wdb_t * wdb, struct kv const *kv_value, char *data)
{
    bool ret_val = false;
    if (NULL != data && NULL != wdb && NULL != kv_value) {
        char query[OS_SIZE_2048] = { 0 };
        strcat(query, "UPDATE ");
        strcat(query, kv_value->value);
        strcat(query, " SET ");
        const size_t size = sizeof(char*) * (os_strcnt(data, '|') + 1);
        char ** field_values = (char **)malloc(size);
        char *tok = strtok(data, FIELD_SEPARATOR_DBSYNC);
        char **curr = field_values;

        while (NULL != tok) {
            *curr = tok;
            tok = strtok(NULL, FIELD_SEPARATOR_DBSYNC);
            ++curr;
        }

        if (curr) {
            *curr = NULL;
        }

        bool first_condition_element = true;
        curr = field_values;
        struct column_list const *column = NULL;
        for (column = kv_value->column_list; column ; column=column->next) {
            if (!column->value.is_old_implementation && curr && NULL != *curr) {
                if (!column->value.is_pk && strcmp(*curr, "NULL") != 0) {
                    if (first_condition_element) {
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                        first_condition_element = false;
                    } else {
                        strcat(query, ",");
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                    }
                }
                ++curr;
            }
        }
        strcat(query, " WHERE ");

        first_condition_element = true;
        for (column = kv_value->column_list; column ; column=column->next) {
            if (column->value.is_pk) {
                if (first_condition_element) {
                    strcat(query, column->value.name);
                    strcat(query, "=?");
                    first_condition_element = false;
                } else {
                    strcat(query, " AND ");
                    strcat(query, column->value.name);
                    strcat(query, "=?");
                }
            }
        }
        strcat(query, ";");

        sqlite3_stmt *stmt = wdb_get_cache_stmt(wdb, query);

        if (NULL != stmt) {
            int index = 1;

            curr = field_values;
            for (column = kv_value->column_list; column ; column=column->next) {
                if (!column->value.is_old_implementation && curr && NULL != *curr) {
                    if (!column->value.is_pk && strcmp(*curr, "NULL") != 0) {
                        if (FIELD_TEXT == column->value.type) {
                            if (SQLITE_OK != sqlite3_bind_text(stmt, index, *curr, -1, NULL)) {
                                merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                            }
                        } else {
                            if (SQLITE_OK != sqlite3_bind_int(stmt, index, atoi(*curr))) {
                                merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                            }
                        }
                        ++index;
                    }
                    ++curr;
                }
            }

            curr = field_values;
            for (column = kv_value->column_list; column ; column=column->next) {
                if (!column->value.is_old_implementation && curr && NULL != *curr) {
                    if (column->value.is_pk && strcmp(*curr, "NULL") != 0) {
                        if (FIELD_TEXT == column->value.type) {
                            if (SQLITE_OK != sqlite3_bind_text(stmt, index, *curr, -1, NULL)) {
                                merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                            }
                        } else {
                            if (SQLITE_OK != sqlite3_bind_int(stmt, index, atoi(*curr))) {
                                merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                            }
                        }
                        ++index;
                    }
                    ++curr;
                }
            }
            ret_val = SQLITE_DONE == wdb_step(stmt);
        } else {
            mdebug1("Cannot get cache statement");
        }
        os_free(field_values);
    }
    return ret_val;
}

bool wdb_delete_dbsync(wdb_t * wdb, struct kv const *kv_value, char *data)
{
    bool ret_val = false;
    if (NULL != wdb && NULL != data) {
        char query[OS_SIZE_2048] = { 0 };
        strcat(query, "DELETE FROM ");
        strcat(query, kv_value->value);
        strcat(query, " WHERE ");

        bool first_condition_element = true;
        struct column_list const *column = NULL;
        for (column = kv_value->column_list; column ; column=column->next) {
            if (!column->value.is_old_implementation) {
                if (column->value.is_pk) {
                    if (first_condition_element) {
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                        first_condition_element = false;
                    } else {
                        strcat(query, " AND ");
                        strcat(query, column->value.name);
                        strcat(query, "=?");
                    }
                }
            }
        }
        strcat(query, ";");

        sqlite3_stmt *stmt = wdb_get_cache_stmt(wdb, query);

        if (NULL != stmt) {
            char *field_value = strtok(data, FIELD_SEPARATOR_DBSYNC);
            struct column_list const *column = NULL;
            int index = 1;
            for (column = kv_value->column_list; column ; column=column->next) {
                if (!column->value.is_old_implementation) {
                    if (NULL != field_value) {
                        if (column->value.is_pk) {
                            if (FIELD_TEXT == column->value.type) {
                                if (SQLITE_OK != sqlite3_bind_text(stmt, index, strcmp(field_value, "NULL") == 0 ? "" : field_value, -1, NULL)) {
                                    merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                                }
                            } else {
                                if (SQLITE_OK != sqlite3_bind_int(stmt, index, strcmp(field_value, "NULL") == 0 ? 0 : atoi(field_value))) {
                                    merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                                }
                            }
                            ++index;
                        }
                        if (column->next) {
                            field_value = strtok(NULL, FIELD_SEPARATOR_DBSYNC);
                        }
                    }
                }
            }
            ret_val = SQLITE_DONE == wdb_step(stmt);
        } else {
            mdebug1("Cannot get cache statement");
        }
    }
    return ret_val;
}
