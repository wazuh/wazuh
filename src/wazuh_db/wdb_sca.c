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
#include "os_crypto/sha256/sha256_op.h"

/* Look for a configuration assessment entry in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_find(wdb_t * wdb, int pm_id, char * output) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_FIND) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_FIND];

    sqlite3_bind_int(stmt, 1, pm_id);

    switch (wdb_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 1));
            return 1;
            break;
        case SQLITE_DONE:
            return 0;
            break;
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}

/* Insert configuration assessment entry. Returns 0 on success or -1 on error (new) */
int wdb_sca_save(wdb_t *wdb, int id, int scan_id, char *title, char *description,
        char *rationale, char *remediation, char *condition, char *file,
        char *directory, char *process, char *registry, char *reference,
        char *result, char *policy_id, char *command, char *reason)
{
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_INSERT) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_INSERT];

    sqlite3_bind_int(stmt, 1, id);
    sqlite3_bind_int(stmt, 2, scan_id);
    sqlite3_bind_text(stmt, 3, title, -1, NULL);
    sqlite3_bind_text(stmt, 4, description, -1, NULL);
    sqlite3_bind_text(stmt, 5, rationale, -1, NULL);
    sqlite3_bind_text(stmt, 6, remediation, -1, NULL);
    sqlite3_bind_text(stmt, 7, file, -1, NULL);
    sqlite3_bind_text(stmt, 8, directory, -1, NULL);
    sqlite3_bind_text(stmt, 9, process, -1, NULL);
    sqlite3_bind_text(stmt, 10, registry, -1, NULL);
    sqlite3_bind_text(stmt, 11, reference, -1, NULL);
    sqlite3_bind_text(stmt, 12, result, -1, NULL);
    sqlite3_bind_text(stmt, 13, policy_id, -1, NULL);
    sqlite3_bind_text(stmt, 14, command, -1, NULL);
    sqlite3_bind_text(stmt, 15, reason, -1, NULL);
    sqlite3_bind_text(stmt, 16, condition, -1, NULL);

    switch (wdb_step(stmt)) {
        case SQLITE_DONE:
            return 0;
        case SQLITE_CONSTRAINT:
            if (!strncmp(sqlite3_errmsg(wdb->db), "UNIQUE", 6)) {
                mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
                return 0;
            } else {
                merror("SQLite: %s", sqlite3_errmsg(wdb->db));
                return -1;
            }
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}

int wdb_sca_policy_get_id(wdb_t * wdb, char * output) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_POLICY_GET_ALL) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_POLICY_GET_ALL];

    char *str = NULL;
    int has_result = 0;

    while(1) {
        switch (wdb_step(stmt)) {
            case SQLITE_ROW:
                has_result = 1;
                wm_strcat(&str,(const char *)sqlite3_column_text(stmt, 0),',');
                break;
            case SQLITE_DONE:
                goto end;
                break;
            default:
                merror("SQLite: %s", sqlite3_errmsg(wdb->db));
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

/* Delete a configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_policy_delete(wdb_t * wdb,char * policy_id) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_POLICY_DELETE) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_POLICY_DELETE];

    sqlite3_bind_text(stmt, 1, policy_id, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        wdb_sca_scan_info_delete(wdb,policy_id);
        return 0;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Delete a configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_scan_info_delete(wdb_t * wdb,char * policy_id) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_SCAN_INFO_DELETE) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_SCAN_INFO_DELETE];

    sqlite3_bind_text(stmt, 1, policy_id, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Delete distinct configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_delete_distinct(wdb_t * wdb,char * policy_id,int scan_id) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_CHECK_DELETE_DISTINCT) < 0) {
        mdebug1("at wdb_sca_check_delete_distinct(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_CHECK_DELETE_DISTINCT];

    sqlite3_bind_int(stmt, 1, scan_id);
    sqlite3_bind_text(stmt, 2, policy_id, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_check_delete(wdb_t * wdb,char * policy_id) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_CHECK_DELETE) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_CHECK_DELETE];

    sqlite3_bind_text(stmt, 1, policy_id, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_check_compliances_delete(wdb_t * wdb) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_CHECK_COMPLIANCE_DELETE) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_CHECK_COMPLIANCE_DELETE];

    if (wdb_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_check_rules_delete(wdb_t * wdb) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_CHECK_RULES_DELETE) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_CHECK_RULES_DELETE];

    if (wdb_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Look for a scan configuration assessment entry in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_scan_find(wdb_t * wdb, char *policy_id, char * output) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_FIND_SCAN) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_FIND_SCAN];

    sqlite3_bind_text(stmt, 1, policy_id, -1, NULL);

    switch (wdb_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s %d", sqlite3_column_text(stmt, 1),sqlite3_column_int(stmt, 2));
            return 1;
            break;
        case SQLITE_DONE:
            return 0;
            break;
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}

int wdb_sca_policy_find(wdb_t * wdb, char *id, char * output) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_POLICY_FIND) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_POLICY_FIND];

    sqlite3_bind_text(stmt, 1, id, -1, NULL);

    switch (wdb_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 0));
            return 1;
            break;
        case SQLITE_DONE:
            return 0;
            break;
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}

int wdb_sca_policy_sha256(wdb_t * wdb, char *id, char * output) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_POLICY_SHA256) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_POLICY_SHA256];
    sqlite3_bind_text(stmt, 1, id, -1, NULL);

    switch (wdb_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 0));
            return 1;
            break;
        case SQLITE_DONE:
            return 0;
            break;
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}

int wdb_sca_compliance_save(wdb_t * wdb, int id_check, char *key, char *value) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_INSERT_COMPLIANCE) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_INSERT_COMPLIANCE];

    sqlite3_bind_int(stmt, 1, id_check);
    sqlite3_bind_text(stmt, 2, key, -1, NULL);
    sqlite3_bind_text(stmt, 3, value, -1, NULL);

    switch (wdb_step(stmt)) {
        case SQLITE_DONE:
            return 0;
        case SQLITE_CONSTRAINT:
            if (!strncmp(sqlite3_errmsg(wdb->db), "UNIQUE", 6)) {
                mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
                return 0;
            } else {
                merror("SQLite: %s", sqlite3_errmsg(wdb->db));
                return -1;
            }
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}

int wdb_sca_rules_save(wdb_t * wdb, int id_check, char *type, char *rule){
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

     sqlite3_stmt *stmt = NULL;

     if (wdb_stmt_cache(wdb, WDB_STMT_SCA_INSERT_RULES) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

     stmt = wdb->stmt[WDB_STMT_SCA_INSERT_RULES];

    sqlite3_bind_int(stmt, 1, id_check);
    sqlite3_bind_text(stmt, 2, type, -1, NULL);
    sqlite3_bind_text(stmt, 3, rule, -1, NULL);

    switch (wdb_step(stmt)) {
        case SQLITE_DONE:
            return 0;
        case SQLITE_CONSTRAINT:
            if (!strncmp(sqlite3_errmsg(wdb->db), "UNIQUE", 6)) {
                mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
                return 0;
            } else {
                merror("SQLite: %s", sqlite3_errmsg(wdb->db));
                return -1;
            }
        default:
            merror("SQLite: %s", sqlite3_errmsg(wdb->db));
            return -1;
    }
}


/* Insert policy entry. Returns 0 on success or -1 on error (new) */
int wdb_sca_policy_info_save(wdb_t * wdb,char *name,char * file,char * id,char * description,char *references, char *hash_file) {

     if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_POLICY_INSERT) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_POLICY_INSERT];

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, file, -1, NULL);
    sqlite3_bind_text(stmt, 3, id, -1, NULL);
    sqlite3_bind_text(stmt, 4, description, -1, NULL);
    sqlite3_bind_text(stmt, 5, references, -1, NULL);
    sqlite3_bind_text(stmt, 6, hash_file, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Insert configuration assessment entry. Returns 0 on success or -1 on error (new) */
int wdb_sca_scan_info_save(wdb_t * wdb, int start_scan, int end_scan, int scan_id,char * policy_id,int pass,int fail,int invalid, int total_checks,int score,char * hash) {

     if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_SCAN_INFO_INSERT) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_SCAN_INFO_INSERT];

    sqlite3_bind_int(stmt, 1, start_scan);
    sqlite3_bind_int(stmt, 2, end_scan);
    sqlite3_bind_int(stmt, 3, scan_id);
    sqlite3_bind_text(stmt, 4, policy_id, -1, NULL);
    sqlite3_bind_int(stmt, 5, pass);
    sqlite3_bind_int(stmt, 6, fail);
    sqlite3_bind_int(stmt, 7, invalid);
    sqlite3_bind_int(stmt, 8, total_checks);
    sqlite3_bind_int(stmt, 9, score);
    sqlite3_bind_text(stmt, 10, hash, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_scan_info_update(wdb_t * wdb, char * module, int end_scan){
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_SCAN_INFO_UPDATE) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_SCAN_INFO_UPDATE];

    sqlite3_bind_int(stmt, 1, end_scan);
    sqlite3_bind_text(stmt, 2, module, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_scan_info_update_start(wdb_t * wdb, char * policy_id, int start_scan,int end_scan,int scan_id,int pass,int fail,int invalid, int total_checks,int score,char * hash) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_SCAN_INFO_UPDATE_START) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_SCAN_INFO_UPDATE_START];

    sqlite3_bind_int(stmt, 1, start_scan);
    sqlite3_bind_int(stmt, 2, end_scan);
    sqlite3_bind_int(stmt, 3, scan_id);
    sqlite3_bind_int(stmt, 4, pass);
    sqlite3_bind_int(stmt, 5, fail);
    sqlite3_bind_int(stmt, 6, invalid);
    sqlite3_bind_int(stmt, 7, total_checks);
    sqlite3_bind_int(stmt, 8, score);
    sqlite3_bind_text(stmt, 9, hash, -1, NULL);
    sqlite3_bind_text(stmt, 10, policy_id, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Gets the result of all checks in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_checks_get_result(wdb_t * wdb, char * policy_id, char * output) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_CHECK_GET_ALL_RESULTS) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_CHECK_GET_ALL_RESULTS];

    sqlite3_bind_text(stmt, 1, policy_id,-1, NULL);

    char *str = NULL;
    int has_result = 0;

    while(1) {
        switch (wdb_step(stmt)) {
            case SQLITE_ROW:
                has_result = 1;
                wm_strcat(&str,(const char *)sqlite3_column_text(stmt, 0),':');
                break;
            case SQLITE_DONE:
                goto end;
                break;
            default:
                merror("SQLite: %s", sqlite3_errmsg(wdb->db));
                os_free(str);
                return -1;
        }
    }

end:
    if(has_result) {
        if(str) {
            char * results = wstr_replace(str, "not applicable", "");

            os_sha256 hash;
            OS_SHA256_String(results, hash);
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", hash);
            os_free(str);
            os_free(results);
        }
        return 1;
    }
    return 0;
}

/* Update a configuration assessment entry. Returns affected rows on success or -1 on error (new) */
int wdb_sca_update(wdb_t * wdb, char * result, int id, int scan_id, char * reason) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_UPDATE) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_UPDATE];

    sqlite3_bind_int(stmt, 1, scan_id);

    sqlite3_bind_text(stmt, 2, result,-1, NULL);
    sqlite3_bind_text(stmt, 3, reason,-1, NULL);
    sqlite3_bind_int(stmt, 4, id);

    if (wdb_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("SQLite: %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}
