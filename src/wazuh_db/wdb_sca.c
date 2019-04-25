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

static const char *SQL_INSERT_PM = "INSERT INTO pm_event (date_first, date_last, log, pci_dss, cis) VALUES (datetime(?, 'unixepoch', 'localtime'), datetime(?, 'unixepoch', 'localtime'), ?, ?, ?);";
static const char *SQL_UPDATE_PM = "UPDATE pm_event SET date_last = datetime(?, 'unixepoch', 'localtime') WHERE log = ?;";
static const char *SQL_DELETE_PM = "DELETE FROM pm_event;";

/* Get PCI_DSS requirement from log string */
static char* get_pci_dss(const char *string);

/* Get CIS requirement from log string */
char* get_cis(const char *string);

/* Insert configuration assessment entry. Returns ID on success or -1 on error. */
int wdb_insert_pm(sqlite3 *db, const rk_event_t *event) {
    sqlite3_stmt *stmt = NULL;
    int result;
    char *pci_dss;
    char *cis;

    if (wdb_prepare(db, SQL_INSERT_PM, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    pci_dss = get_pci_dss(event->log);
    cis = get_cis(event->log);

    sqlite3_bind_int(stmt, 1, event->date_first);
    sqlite3_bind_int(stmt, 2, event->date_last);
    sqlite3_bind_text(stmt, 3, event->log, -1, NULL);
    sqlite3_bind_text(stmt, 4, pci_dss, -1, NULL);
    sqlite3_bind_text(stmt, 5, cis, -1, NULL);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_last_insert_rowid(db) : -1;
    sqlite3_finalize(stmt);
    free(pci_dss);
    free(cis);
    return result;
}

/* Update configuration assessment last date. Returns number of affected rows on success or -1 on error. */
int wdb_update_pm(sqlite3 *db, const rk_event_t *event) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_prepare(db, SQL_UPDATE_PM, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        return -1;
    }

    sqlite3_bind_int(stmt, 1, event->date_last);
    sqlite3_bind_text(stmt, 2, event->log, -1, NULL);

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(db) : -1;
    sqlite3_finalize(stmt);
    return result;
}

/* Delete PM events of an agent. Returns 0 on success or -1 on error. */
int wdb_delete_pm(int id) {
    sqlite3 *db;
    sqlite3_stmt *stmt;
    char *name = id ? wdb_agent_name(id) : strdup("localhost");
    int result;

    if (!name)
        return -1;

    db = wdb_open_agent(id, name);
    free(name);

    if (!db)
        return -1;

    if (wdb_prepare(db, SQL_DELETE_PM, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(db));
        sqlite3_close_v2(db);
        return -1;
    }

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(db) : -1;
    sqlite3_finalize(stmt);
    wdb_vacuum(db);
    sqlite3_close_v2(db);
    return result;
}

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

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 1));

            if (strcmp(output, "failed") && strcmp(output,"passed")) {
                snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 2));
            }
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

/* Insert configuration assessment entry. Returns 0 on success or -1 on error (new) */
int wdb_sca_save(wdb_t * wdb, int id,int scan_id,char * title,char *description,char *rationale,char *remediation, char * file,char * directory,char * process,char * registry,char * reference,char * result,char * policy_id,char * command,char *status,char *reason) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_save(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_INSERT) < 0) {
        mdebug1("at wdb_sca_save(): cannot cache statement");
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
    sqlite3_bind_text(stmt, 15, status, -1, NULL);
    sqlite3_bind_text(stmt, 16, reason, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Update global configuration assessment entry. Returns number of affected rows or -1 on error.  */
int wdb_sca_global_update(wdb_t * wdb, int scan_id, char *name,char *description,char *references,int pass,int failed,int score) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_global_update(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_GLOBAL_UPDATE) < 0) {
        mdebug1("at wdb_sca_global_update(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_GLOBAL_UPDATE];

    sqlite3_bind_int(stmt, 1, scan_id);
    sqlite3_bind_text(stmt, 2, name, -1, NULL);
    sqlite3_bind_text(stmt, 3, description, -1, NULL);
    sqlite3_bind_text(stmt, 4, references, -1, NULL);
    sqlite3_bind_int(stmt, 5, pass);
    sqlite3_bind_int(stmt, 6, failed);
    sqlite3_bind_int(stmt, 7, score);
    sqlite3_bind_text(stmt, 8, name, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Look for a configuration assessment entry in Wazuh DB. Returns 1 if found, 0 if not, or -1 on error. (new) */
int wdb_sca_global_find(wdb_t * wdb, char *name, char * output) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_GLOBAL_FIND) < 0) {
        mdebug1("cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_GLOBAL_FIND];

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

/* Delete a configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_policy_delete(wdb_t * wdb,char * policy_id) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_policy_delete(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_POLICY_DELETE) < 0) {
        mdebug1("at wdb_sca_policy_delete(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_POLICY_DELETE];

    sqlite3_bind_text(stmt, 1, policy_id, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        wdb_sca_scan_info_delete(wdb,policy_id);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Delete a configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_scan_info_delete(wdb_t * wdb,char * policy_id) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_scan_info_delete(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_SCAN_INFO_DELETE) < 0) {
        mdebug1("at wdb_sca_scan_info_delete(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_SCAN_INFO_DELETE];

    sqlite3_bind_text(stmt, 1, policy_id, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Delete distinct configuration assessment policy. Returns 0 on success or -1 on error (new) */
int wdb_sca_check_delete_distinct(wdb_t * wdb,char * policy_id,int scan_id) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_check_delete_distinct(): cannot begin transaction");
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
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_check_delete(wdb_t * wdb,char * policy_id) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_check_delete(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_CHECK_DELETE) < 0) {
        mdebug1("at wdb_sca_check_delete(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_CHECK_DELETE];

    sqlite3_bind_text(stmt, 1, policy_id, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_check_compliances_delete(wdb_t * wdb) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_check_compliances_delete(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_CHECK_COMPLIANCE_DELETE) < 0) {
        mdebug1("at wdb_sca_check_compliances_delete(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_CHECK_COMPLIANCE_DELETE];
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_check_rules_delete(wdb_t * wdb) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_check_rules_delete(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_CHECK_RULES_DELETE) < 0) {
        mdebug1("at wdb_sca_check_rules_delete(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_CHECK_RULES_DELETE];
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
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

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s %d", sqlite3_column_text(stmt, 1),sqlite3_column_int(stmt, 2));
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

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 0));
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

    switch (sqlite3_step(stmt)) {
        case SQLITE_ROW:
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 0));
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

int wdb_sca_compliance_save(wdb_t * wdb, int id_check, char *key, char *value) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_compliance_save(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_INSERT_COMPLIANCE) < 0) {
        mdebug1("at wdb_sca_compliance_save(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_INSERT_COMPLIANCE];

    sqlite3_bind_int(stmt, 1, id_check);
    sqlite3_bind_text(stmt, 2, key, -1, NULL);
    sqlite3_bind_text(stmt, 3, value, -1, NULL);
    
    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_rules_save(wdb_t * wdb, int id_check, char *type, char *rule){
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_rules_save(): cannot begin transaction");
        return -1;
    }

     sqlite3_stmt *stmt = NULL;

     if (wdb_stmt_cache(wdb, WDB_STMT_SCA_INSERT_RULES) < 0) {
        mdebug1("at wdb_sca_rules_save(): cannot cache statement");
        return -1;
    }

     stmt = wdb->stmt[WDB_STMT_SCA_INSERT_RULES];

    sqlite3_bind_int(stmt, 1, id_check);
    sqlite3_bind_text(stmt, 2, type, -1, NULL);
    sqlite3_bind_text(stmt, 3, rule, -1, NULL);

     if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}


/* Insert policy entry. Returns 0 on success or -1 on error (new) */
int wdb_sca_policy_info_save(wdb_t * wdb,char *name,char * file,char * id,char * description,char *references, char *hash_file) {

     if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_policy_info_save(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_POLICY_INSERT) < 0) {
        mdebug1("at wdb_sca_policy_info_save(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_POLICY_INSERT];

    sqlite3_bind_text(stmt, 1, name, -1, NULL);
    sqlite3_bind_text(stmt, 2, file, -1, NULL);
    sqlite3_bind_text(stmt, 3, id, -1, NULL);
    sqlite3_bind_text(stmt, 4, description, -1, NULL);
    sqlite3_bind_text(stmt, 5, references, -1, NULL);
    sqlite3_bind_text(stmt, 6, hash_file, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
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

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_scan_info_update(wdb_t * wdb, char * module, int end_scan){
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_scan_info_update(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_SCAN_INFO_UPDATE) < 0) {
        mdebug1("at wdb_sca_scan_info_update(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_SCAN_INFO_UPDATE];

    sqlite3_bind_int(stmt, 1, end_scan);
    sqlite3_bind_text(stmt, 2, module, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("at wdb_sca_scan_info_update(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_check_update_scan_id(wdb_t * wdb, __attribute__((unused))int scan_id_old,int scan_id_new,char * policy_id){
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_check_update_scan_id(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_CHECK_UPDATE_SCAN_ID) < 0) {
        mdebug1("at wdb_sca_check_update_scan_id(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_CHECK_UPDATE_SCAN_ID];

    sqlite3_bind_int(stmt, 1, scan_id_new);
    sqlite3_bind_text(stmt, 2, policy_id,-1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("at wdb_sca_check_update_scan_id(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

int wdb_sca_scan_info_update_start(wdb_t * wdb, char * policy_id, int start_scan,int end_scan,int scan_id,int pass,int fail,int invalid, int total_checks,int score,char * hash) {
    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_scan_info_update_start(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_SCAN_INFO_UPDATE_START) < 0) {
        mdebug1("at wdb_sca_scan_info_update_start(): cannot cache statement");
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

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("at wdb_sca_scan_info_update_start(): sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
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
        switch (sqlite3_step(stmt)) {
            case SQLITE_ROW:
                has_result = 1;
                wm_strcat(&str,(const char *)sqlite3_column_text(stmt, 0),':');
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
        if(str) {
            os_sha256 hash;
            OS_SHA256_String(str,hash);
            snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", hash);
            os_free(str);
        }
        return 1;
    }
    return 0;
}

/* Update a configuration assessment entry. Returns affected rows on success or -1 on error (new) */
int wdb_sca_update(wdb_t * wdb, char * result, int id,int scan_id, char * status, char * reason) {

    if (!wdb->transaction && wdb_begin2(wdb) < 0){
        mdebug1("at wdb_sca_update(): cannot begin transaction");
        return -1;
    }

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_SCA_UPDATE) < 0) {
        mdebug1("at wdb_sca_update(): cannot cache statement");
        return -1;
    }

    stmt = wdb->stmt[WDB_STMT_SCA_UPDATE];

    sqlite3_bind_text(stmt, 1, result,-1, NULL);

    sqlite3_bind_int(stmt, 2, scan_id);
    sqlite3_bind_text(stmt, 3, status,-1, NULL);
    sqlite3_bind_text(stmt, 4, reason,-1, NULL);
    sqlite3_bind_int(stmt, 5, id);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        return sqlite3_changes(wdb->db);
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        return -1;
    }
}

/* Delete PM events of all agents */
void wdb_delete_pm_all() {
    int *agents = wdb_get_all_agents();
    int i;

    if (agents) {
        wdb_delete_pm(0);

        for (i = 0; agents[i] >= 0; i++)
            wdb_delete_pm(agents[i]);

        free(agents);
    }
}

/* Get PCI_DSS requirement from log string */
char* get_pci_dss(const char *string) {
    size_t length;
    char *out = strstr(string, "{PCI_DSS: ");

    if (out) {
        out += 10;
        length = strcspn(out, "}");

        if (length < strlen(out)) {
            out = strdup(out);
            out[length] = '\0';
            return out;
        }
    }
        return NULL;
}

/* Get CIS requirement from log string */
char* get_cis(const char *string) {
    size_t length;
    char *out = strstr(string, "{CIS: ");

    if (out) {
        out += 6;
        length = strcspn(out, "}");

        if (length < strlen(out)) {
            out = strdup(out);
            out[length] = '\0';
            return out;
        }
    }
        return NULL;
}
