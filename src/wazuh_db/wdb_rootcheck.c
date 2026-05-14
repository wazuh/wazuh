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
#include "helpers/wdb_global_helpers.h"

/* Get PCI_DSS requirement from log string */
static char* get_pci_dss(const char *string);

/* Get CIS requirement from log string */
char* get_cis(const char *string);

/* Insert configuration assessment entry. Returns ID on success or -1 on error. */
int wdb_rootcheck_insert(wdb_t * wdb, const rk_event_t *event) {
    sqlite3_stmt *stmt = NULL;
    int result;
    char *pci_dss;
    char *cis;

    if (wdb_stmt_cache(wdb, WDB_STMT_ROOTCHECK_INSERT_PM)) {
        merror("DB(%s) Cannot cache statement", wdb->id);
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_ROOTCHECK_INSERT_PM];

    pci_dss = get_pci_dss(event->log);
    cis = get_cis(event->log);

    sqlite3_bind_int(stmt, 1, event->date_first);
    sqlite3_bind_int(stmt, 2, event->date_last);
    sqlite3_bind_text(stmt, 3, event->log, -1, NULL);
    sqlite3_bind_text(stmt, 4, pci_dss, -1, NULL);
    sqlite3_bind_text(stmt, 5, cis, -1, NULL);

    result = wdb_step(stmt) == SQLITE_DONE ? (int)sqlite3_last_insert_rowid(wdb->db) : -1;
    free(pci_dss);
    free(cis);
    return result;
}

/* Update configuration assessment last date. Returns number of affected rows on success or -1 on error. */
int wdb_rootcheck_update(wdb_t * wdb, const rk_event_t *event) {
    sqlite3_stmt *stmt = NULL;
    int result;

    if (wdb_stmt_cache(wdb, WDB_STMT_ROOTCHECK_UPDATE_PM)) {
        merror("DB(%s) Cannot cache statement", wdb->id);
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_ROOTCHECK_UPDATE_PM];

    sqlite3_bind_int(stmt, 1, event->date_last);
    sqlite3_bind_text(stmt, 2, event->log, -1, NULL);

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(wdb->db) : -1;
    return result;
}

int wdb_rootcheck_delete(wdb_t * wdb) {
    sqlite3_stmt *stmt;
    int result;


    if (wdb_stmt_cache(wdb, WDB_STMT_ROOTCHECK_DELETE_PM)) {
        merror("DB(%s) Cannot cache statement", wdb->id);
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_ROOTCHECK_DELETE_PM];

    result = wdb_step(stmt) == SQLITE_DONE ? sqlite3_changes(wdb->db) : -1;
    return result;
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
