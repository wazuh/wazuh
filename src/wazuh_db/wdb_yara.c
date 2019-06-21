/*
 * Wazuh SQLite integration
 * Copyright (C) 2015-2019, Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "wdb.h"
#include "os_crypto/sha256/sha256_op.h"

/* Insert yara set data. Returns ID on success or -1 on error */
int wdb_yara_save_set_data(wdb_t * wdb, char *name, char *description) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_save_set_data(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_INSERT_SET) < 0) {
        mdebug1("at wdb_yara_save_set_data(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_INSERT_SET];

    sqlite3_bind_text(stmt, 1, name,-1, NULL);
    sqlite3_bind_text(stmt, 2, description, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Find yara set data. Returns NAME on success or -1 on error */
int wdb_yara_find_set_data(wdb_t * wdb, char *name, char *output) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_SELECT_SET) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_SELECT_SET];

    sqlite3_bind_text(stmt, 1, name, -1, NULL);

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 1));
            return 1;
            break;
        case SQLITE_DONE:
            return 0;
            break;
        default:
            merror(" at sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}


/* Insert yara set rule data. Returns ID on success or -1 on error */
int wdb_yara_save_set_rule_data(wdb_t * wdb, char *set_name, char *path, char *description) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_save_set_rule_data(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_INSERT_SET_RULE) < 0) {
        mdebug1("at wdb_yara_save_set_rule_data(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_INSERT_SET_RULE];

    sqlite3_bind_text(stmt, 1, set_name,-1, NULL);
    sqlite3_bind_text(stmt, 2, path, -1, NULL);
    sqlite3_bind_text(stmt, 3, description, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Find yara set data rule. Returns ID on success or -1 on error */
int wdb_yara_find_set_rule_data(wdb_t * wdb, char *set_name, char *path, char *output) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_SELECT_SET_RULE) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_SELECT_SET_RULE];

    sqlite3_bind_text(stmt, 1, set_name, -1, NULL);
    sqlite3_bind_text(stmt, 2, path, -1, NULL);

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 1));
            return 1;
            break;
        case SQLITE_DONE:
            return 0;
            break;
        default:
            merror(" at sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}

/* Delete yara set rule. Returns ID on success or -1 on error */
int wdb_yara_delete_set_rule_data(wdb_t * wdb, char *set_name) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_delete_set_rule_data(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_DELETE_SET_RULES) < 0) {
        mdebug1("at wdb_yara_delete_set_rule_data(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_DELETE_SET_RULES];

    sqlite3_bind_text(stmt, 1, set_name, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Updates yara set data. Returns ID on success or -1 on error */
int wdb_yara_update_set_data(wdb_t * wdb, char *name, char *description) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_update_set_data(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_UPDATE_SET) < 0) {
        mdebug1("at wdb_yara_update_set_data(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_UPDATE_SET];

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, description, -1, NULL);
    sqlite3_bind_text(stmt, 3, name, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_yara_get_sets(wdb_t * wdb, char *output) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_GET_SETS) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_GET_SETS];

    char *str = NULL;
    int has_result = 0;

    while(1) {
        switch (sqlite3_step(stmt)) {
            case SQLITE_ROW:
                has_result = 1;
                wm_strcat(&str,(const char *)sqlite3_column_text(stmt, 0),',');
                break;
            case SQLITE_DONE:
                goto end;
                break;
            default:
                merror(" at sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
                os_free(str);
                return -1;
        }
    }

end:
    if(has_result) {
        snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", str);
        os_free(str);
        return 1;
    }
    return 0;
}

int wdb_yara_delete_set(wdb_t * wdb, char *set_name) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_delete_set(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_DELETE_SET) < 0) {
        mdebug1("at wdb_yara_delete_set(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_DELETE_SET];

    sqlite3_bind_text(stmt, 1, set_name, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_yara_find_rule(wdb_t * wdb, char *name, char *namespace) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_find_rule(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_SELECT_RULE) < 0) {
        mdebug1("at wdb_yara_find_rule(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_SELECT_RULE];

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, namespace, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_yara_insert_rule(wdb_t * wdb, char *name, char *namespace, char *set_name) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_insert_rule(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_INSERT_RULE) < 0) {
        mdebug1("at wdb_yara_insert_rule(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_INSERT_RULE];

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, namespace, -1, NULL);
    sqlite3_bind_text(stmt, 3, set_name, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_yara_insert_rule_metadata(wdb_t * wdb, char *rule_id, char *set_name, char *key, char *value) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_insert_rule_metadata(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_INSERT_RULE_METADATA) < 0) {
        mdebug1("at wdb_yara_insert_rule_metadata(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_INSERT_RULE_METADATA];

    sqlite3_bind_text(stmt, 1, rule_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, set_name, -1, NULL);
    sqlite3_bind_text(stmt, 3, key, -1, NULL);
    sqlite3_bind_text(stmt, 4, value, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_yara_find_rule_metadata(wdb_t * wdb, char *id_rule, char *set_name, char *namespace) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_find_rule(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_SELECT_RULE_METADATA) < 0) {
        mdebug1("at wdb_yara_find_rule(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_SELECT_RULE_METADATA];

    sqlite3_bind_text(stmt, 1, id_rule, -1, NULL);
    sqlite3_bind_text(stmt, 2, set_name, -1, NULL);
    sqlite3_bind_text(stmt, 3, namespace, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_yara_find_rule_strings(wdb_t * wdb, char *id_rule, char *set_name, char *namespace) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_find_rule(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_SELECT_RULE_STRINGS) < 0) {
        mdebug1("at wdb_yara_find_rule(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_SELECT_RULE_STRINGS];

    sqlite3_bind_text(stmt, 1, id_rule, -1, NULL);
    sqlite3_bind_text(stmt, 2, set_name, -1, NULL);
    sqlite3_bind_text(stmt, 3, namespace, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_yara_insert_rule_strings(wdb_t * wdb, char *rule_id, char *set_name, char *key, char *value) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_insert_rule_strings(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_INSERT_RULE_STRINGS) < 0) {
        mdebug1("at wdb_yara_insert_rule_strings(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_INSERT_RULE_STRINGS];

    sqlite3_bind_text(stmt, 1, rule_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, set_name, -1, NULL);
    sqlite3_bind_text(stmt, 3, key, -1, NULL);
    sqlite3_bind_text(stmt, 4, value, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Delete yara rule from set. Returns ID on success or -1 on error */
int wdb_yara_delete_rules_from_set(wdb_t * wdb, char *set_name) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_delete_rule_from_set(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_DELETE_RULE_FROM_SET) < 0) {
        mdebug1("at wdb_yara_delete_rule_from_set(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_DELETE_RULE_FROM_SET];

    sqlite3_bind_text(stmt, 1, set_name, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Delete yara rule from set. Returns ID on success or -1 on error */
int wdb_yara_delete_rules_metadata_from_set(wdb_t * wdb, char *set_name) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_delete_rule_metadata_from_set(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_DELETE_RULE_METADATA_FROM_SET) < 0) {
        mdebug1("at wdb_yara_delete_rule_metadata_from_set(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_DELETE_RULE_METADATA_FROM_SET];

    sqlite3_bind_text(stmt, 1, set_name, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Delete yara rule from set. Returns ID on success or -1 on error */
int wdb_yara_delete_rules_strings_from_set(wdb_t * wdb, char *set_name) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_delete_rules_strings_from_set(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_DELETE_RULE_STRINGS_FROM_SET) < 0) {
        mdebug1("at wdb_yara_delete_rules_strings_from_set(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_DELETE_RULE_STRINGS_FROM_SET];

    sqlite3_bind_text(stmt, 1, set_name, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Insert yara file. Returns ID on success or -1 on error */
int wdb_yara_insert_file(wdb_t * wdb, char *file, char *rules_matched, char *level0, char *checksum_l0, char *level1, char *checksum_l1, char *level2, char *checksum_l2) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_insert_file(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_INSERT_FILES) < 0) {
        mdebug1("at wdb_yara_insert_file(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_INSERT_FILES];

    sqlite3_bind_text(stmt, 1, file, -1, NULL);
    sqlite3_bind_text(stmt, 2, rules_matched, -1, NULL);
    sqlite3_bind_text(stmt, 3, level0, -1, NULL);
    sqlite3_bind_text(stmt, 4, checksum_l0, -1, NULL);
    sqlite3_bind_text(stmt, 5, level1, -1, NULL);
    sqlite3_bind_text(stmt, 6, checksum_l1, -1, NULL);
    sqlite3_bind_text(stmt, 7, level2, -1, NULL);
    sqlite3_bind_text(stmt, 8, checksum_l2, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Update yara file. Returns ID on success or -1 on error */
int wdb_yara_update_file(wdb_t * wdb, char *file, char *rules_matched, char *level0, char *checksum_l0, char *level1, char *checksum_l1, char *level2, char *checksum_l2) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_update_file(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_UPDATE_FILE) < 0) {
        mdebug1("at wdb_yara_update_file(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_UPDATE_FILE];

    sqlite3_bind_text(stmt, 1, rules_matched, -1, NULL);
    sqlite3_bind_text(stmt, 2, level0, -1, NULL);
    sqlite3_bind_text(stmt, 3, checksum_l0, -1, NULL);
    sqlite3_bind_text(stmt, 4, level1, -1, NULL);
    sqlite3_bind_text(stmt, 5, checksum_l1, -1, NULL);
    sqlite3_bind_text(stmt, 6, level2, -1, NULL);
    sqlite3_bind_text(stmt, 7, checksum_l2, -1, NULL);
    sqlite3_bind_text(stmt, 8, file, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Find yara file. Returns ID on success or -1 on error */
int wdb_yara_find_file(wdb_t * wdb, char *file) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_find_file(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_FIND_FILE) < 0) {
        mdebug1("at wdb_yara_find_file(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_FIND_FILE];

    sqlite3_bind_text(stmt, 1, file, -1, NULL);
    
    int rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_DONE || rc == SQLITE_ROW) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Insert yara scan info. Returns ID on success or -1 on error */
int wdb_yara_save_scan_info(wdb_t * wdb, char *set_name, int start_scan, int end_scan) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_save_scan_info(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_INSERT_SCAN_INFO) < 0) {
        mdebug1("at wdb_yara_save_scan_info(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_INSERT_SCAN_INFO];

    sqlite3_bind_text(stmt, 1, set_name,-1, NULL);
    sqlite3_bind_int(stmt, 2, start_scan);
    sqlite3_bind_int(stmt, 3, end_scan);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Find yara scan info. Returns ID on success or -1 on error */
int wdb_yara_find_scan_info(wdb_t * wdb, char *set_name) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_find_scan_info(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_SELECT_SCAN_INFO) < 0) {
        mdebug1("at wdb_yara_find_scan_info(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_SELECT_SCAN_INFO];

    sqlite3_bind_text(stmt, 1, set_name, -1, NULL);
    
    int rc = sqlite3_step(stmt);
    
    if (rc == SQLITE_DONE || rc == SQLITE_ROW) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Delete yara scan info. Returns ID on success or -1 on error */
int wdb_yara_delete_scan_info(wdb_t * wdb, char *set_name) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_delete_scan_info(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_DELETE_SCAN_INFO) < 0) {
        mdebug1("at wdb_yara_delete_scan_info(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_DELETE_SCAN_INFO];

    sqlite3_bind_text(stmt, 1, set_name, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Update yara scan info. Returns ID on success or -1 on error */
int wdb_yara_update_scan_info(wdb_t * wdb, char *set_name, int start_scan, int end_scan) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0) {
        mdebug1("at wdb_yara_update_scan_info(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_YARA_UPDATE_SCAN_INFO) < 0) {
        mdebug1("at wdb_yara_update_scan_info(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_YARA_UPDATE_SCAN_INFO];

    sqlite3_bind_text(stmt, 1, set_name,-1, NULL);
    sqlite3_bind_int(stmt, 2, start_scan);
    sqlite3_bind_int(stmt, 3, end_scan);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}
