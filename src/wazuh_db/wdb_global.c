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
    ":group_config_status",
    ":status_code",
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

    return wdb_exec_stmt_silent(stmt);
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

    return wdb_exec_stmt_silent(stmt);
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
                                    const char *sync_status,
                                    const char *group_config_status)
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
    if (sqlite3_bind_text(stmt, index++, group_config_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, index++, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
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

    return wdb_exec_stmt_silent(stmt);
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

    return wdb_exec_stmt_silent(stmt);
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

    return wdb_exec_stmt_silent(stmt);
}

int wdb_global_update_agent_connection_status(wdb_t *wdb, int id, const char *connection_status, const char *sync_status, int status_code) {
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
    if (sqlite3_bind_int(stmt, 4, status_code) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }
    if (sqlite3_bind_int(stmt, 5, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}

int wdb_global_update_agent_status_code(wdb_t *wdb, int id, int status_code, const char *version, const char *sync_status) {
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_UPDATE_AGENT_STATUS_CODE) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_UPDATE_AGENT_STATUS_CODE];

    if (sqlite3_bind_int(stmt, 1, status_code) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (sqlite3_bind_text(stmt, 2, version, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (sqlite3_bind_text(stmt, 3, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (sqlite3_bind_int(stmt, 4, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
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

    return wdb_exec_stmt_silent(stmt);
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

int wdb_global_update_agent_groups_hash(wdb_t* wdb, int agent_id, char* groups_string) {
    char groups_hash[WDB_GROUP_HASH_SIZE+1] = {0};

    // If the comma-separated groups string is not sent, read it from 'group' column
    if (groups_string) {
        OS_SHA256_String_sized(groups_string, groups_hash, WDB_GROUP_HASH_SIZE);
    }
    else {
        cJSON* root_j = wdb_global_select_agent_group(wdb, agent_id);
        cJSON* agent_group_j = NULL;
        if (root_j && (agent_group_j = cJSON_GetObjectItem(root_j->child, "group")) && cJSON_IsString(agent_group_j)) {
            OS_SHA256_String_sized(agent_group_j->valuestring, groups_hash, WDB_GROUP_HASH_SIZE);
            cJSON_Delete(root_j);
        }
        else {
            mdebug2("Unable to get group column for agent '%d'. The groups_hash column won't be updated", agent_id);
            cJSON_Delete(root_j);
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

    return wdb_exec_stmt_silent(stmt);
}

int wdb_global_adjust_v4(wdb_t* wdb) {
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

    if (result == OS_SUCCESS && wdb_commit2(wdb) < 0) {
        merror("DB(%s) The commit statement could not be executed.", wdb->id);
        return -1;
    }

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

    if (OS_INVALID == wdb_global_validate_group_name(group_name)) {
        mdebug1("Cannot insert '%s'", group_name);
        return OS_INVALID;
    }

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

    return wdb_exec_stmt_silent(stmt);
}

cJSON* wdb_global_select_group_belong(wdb_t *wdb, int id_agent) {
    sqlite3_stmt *stmt = NULL;

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

    int sql_status = SQLITE_ERROR;
    cJSON *result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status, STMT_SINGLE_COLUMN);

    if (SQLITE_ROW == sql_status) {
        mwarn("The agent's groups exceed the socket maximum response size.");
    } else if (SQLITE_DONE != sql_status) {
        mdebug1("Failed to get agent groups: %s.", sqlite3_errmsg(wdb->db));
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

    return wdb_exec_stmt_silent(stmt);
}

int wdb_global_delete_tuple_belong(wdb_t *wdb, int id_group, int id_agent) {
    sqlite3_stmt *stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_DELETE_TUPLE_BELONG);
    if (stmt == NULL) {
        return OS_INVALID;
    }
    sqlite3_bind_int(stmt, 1, id_group);
    sqlite3_bind_int(stmt, 2, id_agent);

    return wdb_exec_stmt_silent(stmt);
}

cJSON* wdb_is_group_empty(wdb_t *wdb, char* group_name) {
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_BELONG_FIND);
    if (stmt == NULL) {
        return NULL;
    }

    sqlite3_bind_text(stmt, 1, group_name, -1, NULL);

    cJSON* sql_agents_id = wdb_exec_stmt(stmt);

    if (!sql_agents_id) {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return sql_agents_id;
}

int wdb_global_delete_group(wdb_t *wdb, char* group_name) {
    cJSON* sql_agents_id = wdb_is_group_empty(wdb, group_name);

    sqlite3_stmt *stmt = NULL;
    cJSON* agent_id_item = NULL;
    int is_worker = OS_INVALID;
    char* sync_status = NULL;
    int result = OS_INVALID;
    bool err_flag = false;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        cJSON_Delete(sql_agents_id);
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_DELETE_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        cJSON_Delete(sql_agents_id);
        return OS_INVALID;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_DELETE_GROUP];

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        cJSON_Delete(sql_agents_id);
        return OS_INVALID;
    }

    if (OS_SUCCESS == wdb_exec_stmt_silent(stmt)) {
        sync_status = (w_is_single_node(&is_worker) || is_worker)?"synced":"syncreq";
        cJSON_ArrayForEach(agent_id_item, sql_agents_id) {
            cJSON* agent_id = cJSON_GetObjectItem(agent_id_item, "id_agent");
            if (cJSON_IsNumber(agent_id)) {
                if (WDBC_ERROR == wdb_global_if_empty_set_default_agent_group(wdb, agent_id->valueint) ||
                    WDBC_ERROR == wdb_global_recalculate_agent_groups_hash(wdb, agent_id->valueint, sync_status)) {
                    merror("Couldn't recalculate hash group for agent: '%03d'", agent_id->valueint);
                    err_flag = true;
                    break;
                }
            }
        }
        if (!err_flag) {
            result = OS_SUCCESS;
        }
    } else {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
    }

    cJSON_Delete(sql_agents_id);
    return result;
}

cJSON* wdb_global_select_groups(wdb_t *wdb) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_GROUPS) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    sqlite3_stmt *stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_GROUPS];

    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status, STMT_MULTI_COLUMN);

    if (SQLITE_ROW == sql_status) {
        mwarn("The groups exceed the socket maximum response size.");
    } else if (SQLITE_DONE != sql_status) {
        mdebug1("Failed to get groups: %s.", sqlite3_errmsg(wdb->db));
    }

    return result;
}

cJSON* wdb_global_get_group_agents(wdb_t *wdb,  wdbc_result* status, char* group_name, int last_agent_id) {
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_BELONG_GET);
    if (!stmt) {
        *status = WDBC_ERROR;
        return NULL;
    }

    if (sqlite3_bind_text(stmt, 1, group_name, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    if (sqlite3_bind_int(stmt, 2, last_agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status, STMT_SINGLE_COLUMN);

    if (SQLITE_DONE == sql_status) {
        *status = WDBC_OK;
    } else if (SQLITE_ROW == sql_status) {
        *status = WDBC_DUE;
    } else {
        *status = WDBC_ERROR;
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

    return wdb_exec_stmt_silent(stmt);
}

char *wdb_global_validate_sync_status(wdb_t *wdb, int id, const char *requested_sync_status) {
    char *old_sync_status = wdb_global_get_sync_status(wdb, id);

    if (!old_sync_status) {
        merror("Failed to get old sync_status for agent '%d'", id);
        // If we can't validate, allow the requested one by duplicating it
        char *fallback = NULL;
        os_strdup(requested_sync_status, fallback);
        return fallback;
    }

    bool allowed = false;

    if (strcmp(old_sync_status, "synced") == 0 || strcmp(old_sync_status, "syncreq_keepalive") == 0) {
        allowed = true;
    } else if (strcmp(old_sync_status, "syncreq_status") == 0) {
        allowed = strcmp(requested_sync_status, "syncreq_keepalive") != 0;
    } else if (strcmp(old_sync_status, "syncreq") == 0) {
        allowed = strcmp(requested_sync_status, "syncreq_keepalive") != 0 &&
                  strcmp(requested_sync_status, "syncreq_status") != 0;
    }

    char *final_sync_status = NULL;

    if (allowed) {
        os_strdup(requested_sync_status, final_sync_status);
    } else {
        os_strdup(old_sync_status, final_sync_status);
    }

    os_free(old_sync_status);
    return final_sync_status;
}

char * wdb_global_get_sync_status(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = NULL;
    char *sync_status = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SYNC_GET) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SYNC_GET];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    int step = wdb_step(stmt);
    if (step == SQLITE_ROW) {
        const unsigned char *text = sqlite3_column_text(stmt, 0);
        if (text) {
            os_strdup((const char *)text, sync_status);
        }
    } else if (step != SQLITE_DONE) {
        mdebug1("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
    }

    return sync_status;
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

    return wdb_exec_stmt_silent(stmt);
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

    int stmts[] = {
        WDB_STMT_GLOBAL_SYNC_REQ_FULL_GET,
        WDB_STMT_GLOBAL_SYNC_REQ_STATUS_GET,
        WDB_STMT_GLOBAL_SYNC_REQ_KEEPALIVE_GET
    };

    int initial_agent_id = *last_agent_id;

    for (size_t i = 0; i < sizeof(stmts)/sizeof(*stmts); ++i) {
        int stmt_id = stmts[i];

        *last_agent_id = initial_agent_id;
        status = WDBC_UNKNOWN;

        while (status == WDBC_UNKNOWN) {
            //Prepare SQL query
            if (wdb_stmt_cache(wdb, stmt_id) < 0) {
                mdebug1("Cannot cache statement");
                snprintf(*output, WDB_MAX_RESPONSE_SIZE, "%s", "Cannot cache statement");
                status = WDBC_ERROR;
                break;
            }
            agent_stmt = wdb->stmt[stmt_id];
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
                cJSON* json_id = cJSON_GetObjectItem(json_agent, "id");
                if (cJSON_IsNumber(json_id)) {
                    //Get ID
                    int agent_id = json_id->valueint;

                    if (stmt_id == WDB_STMT_GLOBAL_SYNC_REQ_FULL_GET) {
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

        if (status == WDBC_ERROR || status == WDBC_DUE) {
            break;
        }
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
    char* result = NULL;
    sqlite3_stmt *stmt = NULL;

    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return NULL;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_SELECT_GROUP_BELONG) < 0) {
        mdebug1("Cannot cache statement");
        return NULL;
    }

    stmt = wdb->stmt[WDB_STMT_GLOBAL_SELECT_GROUP_BELONG];

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return NULL;
    }

    int _status = SQLITE_ROW;

    while ((_status = wdb_step(stmt)) == SQLITE_ROW) {
        char * group_hash = (char *) sqlite3_column_text(stmt, 0);

        if (group_hash == NULL) {
            mdebug1("Group hash is NULL");
            continue;
        }

        if (result != NULL && WDB_MAX_RESPONSE_SIZE < strlen(result) + strlen(group_hash) + 1) {
            mdebug1("The agent's groups exceed the socket maximum response size.");
            break;
        }
        wm_strcat(&result, group_hash, MULTIGROUP_SEPARATOR);
    }

    if (SQLITE_DONE != _status) {
        mdebug1("SQL statement execution failed");
    }
    return result;
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
    } else {
        mdebug1("Error executing setting the agent group context: %s", sqlite3_errmsg(wdb->db));
        return WDBC_ERROR;
    }
}

wdbc_result wdb_global_set_agent_group_hash(wdb_t *wdb, int id, char* csv, char* hash) {
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_HASH_SET);
    if (stmt == NULL) {
        return WDBC_ERROR;
    }

    sqlite3_bind_text(stmt, 1, csv, -1, NULL);
    sqlite3_bind_text(stmt, 2, hash, -1, NULL);
    sqlite3_bind_int(stmt, 3, id);

    if (OS_SUCCESS == wdb_exec_stmt_silent(stmt)) {
        return WDBC_OK;
    }
    else {
        mdebug1("Error executing setting the agent group hash: %s", sqlite3_errmsg(wdb->db));
        return WDBC_ERROR;
    }
}

cJSON* wdb_global_get_groups_integrity(wdb_t* wdb, os_sha1 hash) {
    sqlite3_stmt* stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_SYNCREQ_FIND);
    if (stmt == NULL) {
        return NULL;
    }

    cJSON* response = NULL;

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        response = cJSON_CreateArray();
        cJSON_AddItemToArray(response, cJSON_CreateString("syncreq"));
        return response;
    case SQLITE_DONE:
        response = cJSON_CreateArray();
        os_sha1 hexdigest = {0};
        if (OS_SUCCESS == wdb_get_global_group_hash(wdb, hexdigest) && !strcmp(hexdigest, hash)) {
            cJSON_AddItemToArray(response, cJSON_CreateString("synced"));
        } else {
            cJSON_AddItemToArray(response, cJSON_CreateString("hash_mismatch"));
        }
        return response;
    default:
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
        return response;
    }
}

int wdb_global_get_agent_max_group_priority(wdb_t *wdb, int id) {
    sqlite3_stmt *stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_GROUP_PRIORITY_GET);
    if (stmt == NULL) {
        return OS_INVALID;
    }

    if (sqlite3_bind_int(stmt, 1, id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    int group_priority = OS_INVALID;
    cJSON* j_result = wdb_exec_stmt(stmt);
    if (j_result) {
        if (j_result->child && j_result->child->child) {
            cJSON* j_priority = j_result->child->child;
            group_priority = j_priority->valueint;
        }
        cJSON_Delete(j_result);
    } else {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return group_priority;
}

wdbc_result wdb_global_assign_agent_group(wdb_t *wdb, int id, cJSON* j_groups, int priority) {
    cJSON* j_group_name = NULL;
    wdbc_result result = WDBC_OK;
    cJSON_ArrayForEach (j_group_name, j_groups) {
        if (cJSON_IsString(j_group_name)) {
            char* group_name = j_group_name->valuestring;
            cJSON* j_find_response = wdb_global_find_group(wdb, group_name);
            if (j_find_response && cJSON_GetArraySize(j_find_response) > 0) {
                cJSON* j_group_id = cJSON_GetObjectItem(j_find_response->child, "id");
                if (cJSON_IsNumber(j_group_id)) {
                    if (OS_INVALID == wdb_global_insert_agent_belong(wdb, j_group_id->valueint, id, priority)) {
                        mdebug1("Unable to insert group '%s' for agent '%d'", group_name, id);
                        result = WDBC_ERROR;
                    } else {
                        priority++;
                    }
                } else {
                    mwarn("Invalid response from wdb_global_find_group.");
                    result = WDBC_ERROR;
                }
            } else {
                mwarn("Unable to find the id of the group '%s'", group_name);
                result = WDBC_ERROR;
            }
            cJSON_Delete(j_find_response);
        } else {
            mdebug1("Invalid groups set information");
            result = WDBC_ERROR;
        }
    }
    return result;
}

wdbc_result wdb_global_unassign_agent_group(wdb_t *wdb, int id, cJSON* j_groups) {
    cJSON* j_group_name = NULL;
    wdbc_result result = WDBC_OK;
    cJSON_ArrayForEach (j_group_name, j_groups) {
        if (cJSON_IsString(j_group_name)) {
            char* group_name = j_group_name->valuestring;
            cJSON* j_find_response = wdb_global_find_group(wdb, group_name);
            if (j_find_response && cJSON_GetArraySize(j_find_response) > 0) {
                cJSON* j_group_id = cJSON_GetObjectItem(j_find_response->child, "id");
                if (cJSON_IsNumber(j_group_id)) {
                    if (OS_SUCCESS == wdb_global_delete_tuple_belong(wdb, j_group_id->valueint, id)) {
                        if (WDBC_ERROR == wdb_global_if_empty_set_default_agent_group(wdb, id)) {
                            result = WDBC_ERROR;
                        }
                    } else {
                        mdebug1("Unable to delete group '%s' for agent '%d'", group_name, id);
                        result = WDBC_ERROR;
                    }
                } else {
                    mwarn("Invalid response from wdb_global_find_group.");
                    result = WDBC_ERROR;
                }
            } else {
                mwarn("Unable to find the id of the group '%s'", group_name);
                result = WDBC_ERROR;
            }
            cJSON_Delete(j_find_response);
        } else {
            mdebug1("Invalid groups remove information");
            result = WDBC_ERROR;
        }
    }

    return result;
}

int wdb_global_if_empty_set_default_agent_group(wdb_t *wdb, int id) {
    int result = WDBC_OK;
    if (OS_INVALID == wdb_global_get_agent_max_group_priority(wdb, id)) {
        cJSON* j_default_group = cJSON_CreateArray();
        cJSON_AddItemToArray(j_default_group, cJSON_CreateString("default"));
        if (WDBC_OK == wdb_global_assign_agent_group(wdb, id, j_default_group, 0)) {
            mdebug1("Agent '%03d' reassigned to 'default' group", id);
        } else {
            merror("There was an error assigning the agent '%03d' to default group", id);
            result = WDBC_ERROR;
        }
        cJSON_Delete(j_default_group);
    }
    return result;
}

int wdb_global_groups_number_get(wdb_t *wdb, int agent_id) {
    sqlite3_stmt *stmt = wdb_init_stmt_in_cache(wdb, WDB_STMT_GLOBAL_AGENT_GROUPS_NUMBER_GET);

    if (stmt == NULL) {
        return OS_INVALID;
    }

    if (sqlite3_bind_int(stmt, 1, agent_id) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    int groups_number = OS_INVALID;
    cJSON* j_result = wdb_exec_stmt(stmt);

    if (j_result) {
        if (j_result->child && j_result->child->child) {
            cJSON* j_groups_number = j_result->child->child;
            groups_number = j_groups_number->valueint;
        }
        cJSON_Delete(j_result);
    } else {
        mdebug1("wdb_exec_stmt(): %s", sqlite3_errmsg(wdb->db));
    }

    return groups_number;
}

w_err_t wdb_global_validate_group_name(const char *group_name) {
    const char *current_directory = ".";
    const char *parent_directory = "..";

    if (strlen(group_name) > MAX_GROUP_NAME) {
        mwarn("Invalid group name. The group '%s' exceeds the maximum length of %d characters permitted", group_name, MAX_GROUP_NAME);
        return OS_INVALID;
    }
    if (!w_regexec("^[a-zA-Z0-9_\\.\\-]+$", group_name, 0, NULL)) {
        mwarn("Invalid group name. '%s' contains invalid characters", group_name);
        return OS_INVALID;
    }
    if (!strcmp(group_name, parent_directory)) {
        mwarn("Invalid group name. '%s' represents the parent directory in unix systems", group_name);
        return OS_INVALID;
    }
    if (!strcmp(group_name, current_directory)) {
        mwarn("Invalid group name. '%s' represents the current directory in unix systems", group_name);
        return OS_INVALID;
    }

    return OS_SUCCESS;
}

w_err_t wdb_global_validate_groups(wdb_t *wdb, cJSON *j_groups, int agent_id) {
    cJSON* j_group_name = NULL;
    wdbc_result ret = OS_SUCCESS;
    int groups_counter = 0;

    int groups_number = wdb_global_groups_number_get(wdb, agent_id);

    if (groups_number != OS_INVALID) {
        cJSON_ArrayForEach (j_group_name, j_groups) {
            if (cJSON_IsString(j_group_name)) {
                ++groups_counter;
                if ((groups_counter + groups_number) > MAX_GROUPS_PER_MULTIGROUP) {
                    mwarn("The groups assigned to agent %03d exceed the maximum of %d permitted.", agent_id, MAX_GROUPS_PER_MULTIGROUP);
                    ret = OS_INVALID;
                    break;
                }
                char* group_name = j_group_name->valuestring;
                if (ret = wdb_global_validate_group_name(group_name), ret) {
                    break;
                }
            }
        }
    } else {
        ret = OS_INVALID;
    }

    return ret;
}

wdbc_result wdb_global_set_agent_groups(wdb_t *wdb, wdb_groups_set_mode_t mode, char* sync_status, cJSON* j_agents_group_info) {
    wdbc_result ret = WDBC_OK;
    cJSON* j_group_info = NULL;
    w_err_t valid_groups = OS_SUCCESS;
    cJSON_ArrayForEach (j_group_info, j_agents_group_info) {
        cJSON* j_agent_id = cJSON_GetObjectItem(j_group_info, "id");
        cJSON* j_groups = cJSON_GetObjectItem(j_group_info, "groups");
        if (cJSON_IsNumber(j_agent_id) && cJSON_IsArray(j_groups)) {
            int agent_id = j_agent_id->valueint;
            int group_priority = 0;

            if (mode == WDB_GROUP_REMOVE) {
                if (WDBC_ERROR ==  wdb_global_unassign_agent_group(wdb, agent_id, j_groups)) {
                    ret = WDBC_ERROR;
                    merror("There was an error un-assigning the groups to agent '%03d'", agent_id);
                }
            } else {
                if (mode == WDB_GROUP_OVERRIDE) {
                    if (OS_INVALID == wdb_global_delete_agent_belong(wdb, agent_id)) {
                        ret = WDBC_ERROR;
                        merror("There was an error cleaning the previous agent groups");
                    }
                } else {
                    int last_group_priority = wdb_global_get_agent_max_group_priority(wdb, agent_id);
                    if (last_group_priority >= 0) {
                        if (mode == WDB_GROUP_EMPTY_ONLY) {
                            mdebug1("Agent group set in empty_only mode ignored because the agent already contains groups");
                            continue;
                        }
                        group_priority = last_group_priority+1;
                    }
                }
                if (valid_groups = wdb_global_validate_groups(wdb, j_groups, agent_id), OS_SUCCESS == valid_groups) {
                    if (WDBC_ERROR == wdb_global_assign_agent_group(wdb, agent_id, j_groups, group_priority)) {
                        ret = WDBC_ERROR;
                        merror("There was an error assigning the groups to agent '%03d'", agent_id);
                    }
                } else {
                    ret = WDBC_ERROR;
                }
            }
            if (OS_SUCCESS == valid_groups) {
                if (WDBC_ERROR == wdb_global_recalculate_agent_groups_hash(wdb, agent_id, sync_status)) {
                    ret = WDBC_ERROR;
                    merror("Couldn't recalculate hash group for agent: '%03d'", agent_id);
                }
            }
        } else {
            ret = WDBC_ERROR;
            mdebug1("Invalid groups set information");
            continue;
        }
    }
    return ret;
}

int wdb_global_recalculate_agent_groups_hash(wdb_t* wdb, int agent_id, char* sync_status) {
    int result = WDBC_OK;
    char* agent_groups_csv = wdb_global_calculate_agent_group_csv(wdb, agent_id);
    char groups_hash[WDB_GROUP_HASH_SIZE+1] = {0};
    if (agent_groups_csv) {
        OS_SHA256_String_sized(agent_groups_csv, groups_hash, WDB_GROUP_HASH_SIZE);
    } else {
        mwarn("The groups were empty right after the set for agent '%03d'", agent_id);
    }
    if (WDBC_ERROR == wdb_global_set_agent_group_context(wdb, agent_id, agent_groups_csv, agent_groups_csv ? groups_hash : NULL, sync_status)) {
        result = WDBC_ERROR;
        merror("There was an error assigning the groups context to agent '%03d'", agent_id);
    }
    os_free(agent_groups_csv);

    wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_CLEAR, NULL);

    return result;
}

int wdb_global_recalculate_agent_groups_hash_without_sync_status(wdb_t* wdb, int agent_id, char* group) {
    int result = WDBC_OK;
    char* agent_groups_csv = wdb_global_calculate_agent_group_csv(wdb, agent_id);
    char groups_hash[WDB_GROUP_HASH_SIZE+1] = {0};

    if (agent_groups_csv) {
        OS_SHA256_String_sized(agent_groups_csv, groups_hash, WDB_GROUP_HASH_SIZE);
    } else {
        mdebug1("No groups in belongs table for agent '%03d'", agent_id);
    }

    // if the previous group is different from the new one, we update the agent group context
    if ((group && !agent_groups_csv) || (!group && agent_groups_csv) || (group && agent_groups_csv && strcmp(group, agent_groups_csv))) {
        if (WDBC_ERROR == wdb_global_set_agent_group_hash(wdb, agent_id, agent_groups_csv, agent_groups_csv ? groups_hash : NULL)) {
            result = WDBC_ERROR;
            merror("There was an error assigning the groups hash to agent '%03d'", agent_id);
        }
    }

    os_free(agent_groups_csv);
    wdb_global_group_hash_cache(WDB_GLOBAL_GROUP_HASH_CLEAR, NULL);

    return result;
}

int wdb_global_recalculate_all_agent_groups_hash(wdb_t* wdb) {

    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS_AND_GROUP) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }
    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS_AND_GROUP];

    if (sqlite3_bind_int(stmt, 1, 0) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    //Get agents to recalculate hash
    int _status = SQLITE_ROW;

    while ((_status = wdb_step(stmt)) == SQLITE_ROW) {
        int id = sqlite3_column_int(stmt, 0);
        char * group = (char *) sqlite3_column_text(stmt, 1);

        if (WDBC_ERROR == wdb_global_recalculate_agent_groups_hash_without_sync_status(wdb, id, group)) {
            merror("Couldn't recalculate hash group for agent: '%03d'", id);
            return OS_INVALID;
        }
    }

    if (SQLITE_DONE != _status) {
        mdebug1("SQL statement execution failed");
    }

    return OS_SUCCESS;
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

wdbc_result wdb_global_sync_agent_groups_get(wdb_t *wdb, wdb_groups_sync_condition_t condition, int last_agent_id, bool set_synced, bool get_hash, int agent_registration_delta, cJSON** output) {
    wdbc_result status = WDBC_UNKNOWN;

    wdb_stmt sync_statement_index = WDB_STMT_GLOBAL_GROUP_SYNC_REQ_GET;
    switch (condition) {
        case WDB_GROUP_SYNC_STATUS:
            sync_statement_index = WDB_STMT_GLOBAL_GROUP_SYNC_REQ_GET;
            break;
        case WDB_GROUP_ALL:
            sync_statement_index = WDB_STMT_GLOBAL_GROUP_SYNC_ALL_GET;
            break;
        case WDB_GROUP_INVALID_CONDITION:
            mdebug1("Invalid groups sync condition");
            return WDBC_ERROR;
        default:
            break;
    }

    *output = cJSON_CreateArray();
    cJSON* j_response = cJSON_CreateObject();
    cJSON* j_data = cJSON_CreateArray();
    cJSON_AddItemToArray(*output, j_response);
    cJSON_AddItemToObject(j_response, "data", j_data);
    char *out_aux = cJSON_PrintUnformatted(*output);
    size_t response_size = strlen(out_aux);
    os_free(out_aux);

    if (condition != WDB_GROUP_NO_CONDITION) {
        if (!wdb->transaction && wdb_begin2(wdb) < 0) {
            mdebug1("Cannot begin transaction");
            return WDBC_ERROR;
        }

        // Agents registered recently may be excluded depending on the 'agent_registration_delta' value.
        time_t agent_registration_time = time(NULL) - agent_registration_delta;

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
            if (sqlite3_bind_int(sync_stmt, 2, agent_registration_time) != SQLITE_OK) {
                merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
                status = WDBC_ERROR;
                break;
            }

            //Get agents to sync
            cJSON* j_agent_stmt = wdb_exec_stmt(sync_stmt);
            if (j_agent_stmt && j_agent_stmt->child) {
                cJSON* j_agent = j_agent_stmt->child;
                cJSON* j_id = cJSON_GetObjectItem(j_agent, "id");
                if (cJSON_IsNumber(j_id)) {
                    //Get agent ID
                    last_agent_id = j_id->valueint;

                    //Get the groups of the agent
                    cJSON* j_groups = wdb_global_select_group_belong(wdb, last_agent_id);
                    if (j_groups && j_groups->child) {
                        cJSON_AddItemToObject(j_agent, "groups", j_groups);
                    } else {
                        cJSON_Delete(j_groups);
                        cJSON_AddItemToObject(j_agent, "groups", cJSON_CreateArray());
                    }

                    //Print Agent groups
                    char *agent_str = cJSON_PrintUnformatted(j_agent);
                    unsigned agent_len = strlen(agent_str);

                    //Check if new agent fits in response
                    if (response_size+agent_len+1 < WDB_MAX_RESPONSE_SIZE) {
                        //Add new agent
                        cJSON_AddItemToArray(j_data, cJSON_Duplicate(j_agent, true));
                        //Save size
                        response_size += agent_len+1;

                        if (set_synced) {
                            //Set groups sync status as synced
                            if (OS_SUCCESS != wdb_global_set_agent_groups_sync_status(wdb, last_agent_id, "synced")) {
                                merror("Cannot set group_sync_status for agent %d", last_agent_id);
                                status = WDBC_ERROR;
                            }
                        }
                    } else {
                        //Pending agents but buffer is full
                        status = WDBC_DUE;
                    }
                    os_free(agent_str);
                } else {
                    //Continue with the next agent
                    last_agent_id++;
                }
            } else {
                //All agents have been obtained
                if (get_hash) {
                    status = wdb_global_add_global_group_hash_to_response(wdb, &j_response, response_size);
                } else {
                    status = WDBC_OK;
                }
            }
            cJSON_Delete(j_agent_stmt);
        }
    } else {
        if (get_hash) {
            status = wdb_global_add_global_group_hash_to_response(wdb, &j_response, response_size);
        } else {
            status = WDBC_OK;
        }
    }

    return status;
}

int wdb_global_add_global_group_hash_to_response(wdb_t *wdb, cJSON** response, size_t response_size) {
    if (response == NULL || !cJSON_IsObject(*response)) {
        mdebug1("Invalid JSON object.");
        return WDBC_ERROR;
    }

    size_t hash_len = strlen("hash:\"\"")+sizeof(os_sha1);
    if (response_size+hash_len+1 < WDB_MAX_RESPONSE_SIZE) {
        os_sha1 hash = {0};
        if (OS_SUCCESS == wdb_get_global_group_hash(wdb, hash)) {
            if (hash[0] == 0) {
                cJSON_AddItemToObject(*response, "hash", cJSON_CreateNull());
            } else {
                cJSON_AddStringToObject(*response, "hash", hash);
            }
        } else {
            merror("Cannot obtain the global group hash");
            return WDBC_ERROR;
        }
        return WDBC_OK;
    }
    return WDBC_DUE;
}

int wdb_global_sync_agent_info_set(wdb_t *wdb, cJSON * json_agent) {
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

    for (n = 0 ; global_db_agent_fields[n] ; n++) {
        // Every column name of Global DB is stored in global_db_agent_fields
        json_field = cJSON_GetObjectItem(json_agent, global_db_agent_fields[n]+1);
        index = sqlite3_bind_parameter_index(stmt, global_db_agent_fields[n]);
        if (cJSON_IsNumber(json_field) && index != 0) {
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

    return wdb_exec_stmt_silent(stmt);
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
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status, STMT_MULTI_COLUMN);
    if (SQLITE_DONE == sql_status) *status = WDBC_OK;
    else if (SQLITE_ROW == sql_status) *status = WDBC_DUE;
    else *status = WDBC_ERROR;

    //Set every obtained agent as 'disconnected'
    cJSON* agent = NULL;
    cJSON_ArrayForEach(agent, result) {
        cJSON* id = cJSON_GetObjectItem(agent, "id");
        if (cJSON_IsNumber(id)) {
            //Set connection status as disconnected
            if (OS_SUCCESS != wdb_global_update_agent_connection_status(wdb, id->valueint, "disconnected", sync_status, NO_KEEPALIVE)) {
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

int wdb_global_get_all_agents_context(wdb_t *wdb) {
    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        return OS_INVALID;
    }

    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS_CONTEXT) < 0) {
        mdebug1("Cannot cache statement");
        return OS_INVALID;
    }
    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS_CONTEXT];

    return wdb_exec_stmt_send(stmt, wdb->peer);
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
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status, STMT_MULTI_COLUMN);
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
        mdebug1("DB(%s) SQLite: %s", wdb->id, sqlite3_errmsg(wdb->db));
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

    if (sqlite3_bind_int(stmt, 1, RESET_BY_MANAGER) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (sqlite3_bind_text(stmt, 2, sync_status, -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    return wdb_exec_stmt_silent(stmt);
}

cJSON* wdb_global_get_agents_by_connection_status (wdb_t *wdb, int last_agent_id, const char* connection_status, const char* node_name, int limit, wdbc_result* status) {
    sqlite3_stmt* stmt;
    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        *status = WDBC_ERROR;
        return NULL;
    }
    if (node_name == NULL) {
        if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS) < 0) {
            mdebug1("Cannot cache statement");
            *status = WDBC_ERROR;
            return NULL;
        }
        stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS];
    } else {
        if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS_AND_NODE) < 0) {
            mdebug1("Cannot cache statement");
            *status = WDBC_ERROR;
            return NULL;
        }
        stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_AGENTS_BY_CONNECTION_STATUS_AND_NODE];
    }
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
    if (node_name != NULL) {
        if (sqlite3_bind_text(stmt, 3, node_name, -1, NULL) != SQLITE_OK) {
            merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            *status = WDBC_ERROR;
            return NULL;
        }
        if (sqlite3_bind_int(stmt, 4, limit) != SQLITE_OK) {
            merror("DB(%s) sqlite3_bind_int(): %s", wdb->id, sqlite3_errmsg(wdb->db));
            *status = WDBC_ERROR;
            return NULL;
        }
    }

    //Execute SQL query limited by size
    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status, STMT_MULTI_COLUMN);
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
    if (wdb_commit2(wdb) < 0) {
        snprintf(output, OS_MAXSTR + 1, "err Cannot commit current transaction to create backup");
        return OS_INVALID;
    }

    // Clear all statements in cache to run VACUUM
    wdb_finalize_all_statements(wdb);

    sqlite3_stmt *stmt = NULL;

    if (sqlite3_prepare_v2(wdb->db, SQL_VACUUM_INTO, -1, &stmt, NULL) != SQLITE_OK) {
        snprintf(output, OS_MAXSTR + 1, "err DB(%s) sqlite3_prepare_v2(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        return OS_INVALID;
    }

    if (sqlite3_bind_text(stmt, 1, path , -1, NULL) != SQLITE_OK) {
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
            minfo("Created Global database backup \"%s\"", path_compressed);
            wdb_global_remove_old_backups();
            cJSON* j_path = cJSON_CreateArray();
            cJSON_AddItemToArray(j_path, cJSON_CreateString(path_compressed));
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
    DIR* dp = wopendir(WDB_BACKUP_FOLDER);

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

    DIR* dp = wopendir(WDB_BACKUP_FOLDER);

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

            wdb_close(*wdb, true);
            unlink(global_path);

            if (rename(global_tmp_path, global_path) != OS_SUCCESS) {
                merror("Renaming %s to %s: %s", global_tmp_path, global_path, strerror(errno));
                result = OS_INVALID;
            }
            else {
                snprintf(output, OS_MAXSTR + 1, "ok");
                result = OS_SUCCESS;
            }
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
    DIR* dp = wopendir(WDB_BACKUP_FOLDER);

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
        if(!w_stat(tmp_path, &backup_info)) {
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
    DIR* dp = wopendir(WDB_BACKUP_FOLDER);

    if(!dp) {
        mdebug1("Unable to open backup directory '%s'", WDB_BACKUP_FOLDER);
        return OS_INVALID;
    }

    struct dirent *entry = NULL;
    time_t oldest_backup_time = OS_INVALID;
    time_t aux_time_var = OS_INVALID;
    time_t current_time = time(NULL);
    char *tmp_backup_name = NULL;

    while (entry = readdir(dp), entry) {
        if (strncmp(entry->d_name, WDB_GLOB_BACKUP_NAME, sizeof(WDB_GLOB_BACKUP_NAME) - 1) != 0) {
            continue;
        }
        char tmp_path[OS_SIZE_512] = {0};
        struct stat backup_info = {0};

        snprintf(tmp_path, OS_SIZE_512, "%s/%s", WDB_BACKUP_FOLDER, entry->d_name);
        if(!w_stat(tmp_path, &backup_info)) {
            if((current_time - backup_info.st_mtime) >= aux_time_var) {
                aux_time_var = current_time - backup_info.st_mtime;
                oldest_backup_time = backup_info.st_mtime;
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

cJSON* wdb_global_get_distinct_agent_groups(wdb_t *wdb, char *group_hash, wdbc_result* status) {
    //Prepare SQL query
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("Cannot begin transaction");
        *status = WDBC_ERROR;
        return NULL;
    }
    if (wdb_stmt_cache(wdb, WDB_STMT_GLOBAL_GET_GROUPS) < 0) {
        mdebug1("Cannot cache statement");
        *status = WDBC_ERROR;
        return NULL;
    }
    sqlite3_stmt* stmt = wdb->stmt[WDB_STMT_GLOBAL_GET_GROUPS];
    if (sqlite3_bind_text(stmt, 1, group_hash != NULL ? group_hash : "", -1, NULL) != SQLITE_OK) {
        merror("DB(%s) sqlite3_bind_text(): %s", wdb->id, sqlite3_errmsg(wdb->db));
        *status = WDBC_ERROR;
        return NULL;
    }

    //Execute SQL query limited by size
    int sql_status = SQLITE_ERROR;
    cJSON* result = wdb_exec_stmt_sized(stmt, WDB_MAX_RESPONSE_SIZE, &sql_status, STMT_MULTI_COLUMN);
    if (SQLITE_DONE == sql_status) *status = WDBC_OK;
    else if (SQLITE_ROW == sql_status) *status = WDBC_DUE;
    else *status = WDBC_ERROR;

    return result;
}
