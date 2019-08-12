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
#include "wdb_mitre.h"

int wdb_mitre_attack_insert(wdb_t *wdb, char *id, char *json){
    sqlite3_stmt *stmt;


    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_ATTACK_INSERT) < 0) {
        mdebug1("at wdb_mitre_attack_insert(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_ATTACK_INSERT];


    sqlite3_bind_text(stmt, 1, id, -1, NULL);
    sqlite3_bind_text(stmt, 2, json, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        w_mutex_lock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_phase_insert(wdb_t *wdb, char *attack_id, char *phase){
    sqlite3_stmt *stmt;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PHASE_INSERT) < 0) {
        mdebug1("at wdb_mitre_phase_insert(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PHASE_INSERT];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, phase, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        w_mutex_lock(&wdb->mutex);
        return 0;
    } else {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_platform_insert(wdb_t *wdb, char *attack_id, char *platform){
    sqlite3_stmt *stmt;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PLATFORM_INSERT) < 0) {
        mdebug1("at wdb_mitre_platform_insert(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PLATFORM_INSERT];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, platform, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        w_mutex_lock(&wdb->mutex);
        return 0;
    } else {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_attack_update(wdb_t *wdb, char *id, char *json){
    sqlite3_stmt *stmt;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_ATTACK_UPDATE) < 0) {
        mdebug1("at wdb_mitre_attack_update(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_ATTACK_UPDATE];

    sqlite3_bind_text(stmt, 1, json, -1, NULL);
    sqlite3_bind_text(stmt, 2, id, -1,  NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        w_mutex_lock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_attack_get(wdb_t *wdb, char *id, char *output){
    sqlite3_stmt *stmt;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_ATTACK_GET) < 0) {
        mdebug1("at wdb_mitre_attack_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_ATTACK_GET];

    sqlite3_bind_text(stmt, 1, id, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        wm_strcat(&output,(const char *)sqlite3_column_text(stmt, 0),':');        
        break;
    case SQLITE_DONE:
        w_mutex_lock(&wdb->mutex);
        return 0;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_phases_get(wdb_t *wdb, char *attack_id, char *output){
    sqlite3_stmt *stmt;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PHASE_GET) < 0) {
        mdebug1("at wdb_mitre_phases_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PHASE_GET];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        wm_strcat(&output,(const char *)sqlite3_column_text(stmt, 0),':');        
        break;
    case SQLITE_DONE:
        w_mutex_lock(&wdb->mutex);
        return 0;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_platforms_get(wdb_t *wdb, char *attack_id, char *output){
    sqlite3_stmt *stmt;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PLATFORM_GET) < 0) {
        mdebug1("at wdb_mitre_phases_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PLATFORM_GET];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        wm_strcat(&output,(const char *)sqlite3_column_text(stmt, 0),':');        
        break;
    case SQLITE_DONE:
        w_mutex_lock(&wdb->mutex);
        return 0;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_attack_delete(wdb_t *wdb, char *id){
    sqlite3_stmt *stmt;
    
    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_ATTACK_DELETE) < 0) {
        mdebug1("at wdb_mitre_attack_delete(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_ATTACK_DELETE];

    sqlite3_bind_text(stmt, 1, id, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        w_mutex_lock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_phase_delete(wdb_t *wdb, char *attack_id){
    sqlite3_stmt *stmt;

   if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PHASE_DELETE) < 0) {
        mdebug1("at wdb_mitre_phase_delete(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PHASE_DELETE];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        w_mutex_lock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_platform_delete(wdb_t *wdb, char *attack_id){
    sqlite3_stmt *stmt;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PLATFORM_DELETE) < 0) {
        mdebug1("at wdb_mitre_phase_delete(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PLATFORM_DELETE];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        w_mutex_lock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}



