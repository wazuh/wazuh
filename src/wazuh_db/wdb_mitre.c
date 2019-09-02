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

int wdb_mitre_attack_insert(wdb_t *wdb, char *id, char *json){
    sqlite3_stmt *stmt;
    w_mutex_lock(&wdb->mutex);

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_ATTACK_INSERT) < 0) {
        mdebug1("at wdb_mitre_attack_insert(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_ATTACK_INSERT];

    sqlite3_bind_text(stmt, 1, id, -1, NULL);
    sqlite3_bind_text(stmt, 2, json, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        w_mutex_unlock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_phase_insert(wdb_t *wdb, char *attack_id, char *phase){
    sqlite3_stmt *stmt;
    w_mutex_lock(&wdb->mutex);

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PHASE_INSERT) < 0) {
        mdebug1("at wdb_mitre_phase_insert(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PHASE_INSERT];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, phase, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE){
        w_mutex_unlock(&wdb->mutex);
        return 0;
    } else {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_platform_insert(wdb_t *wdb, char *attack_id, char *platform){
    sqlite3_stmt *stmt;
    w_mutex_lock(&wdb->mutex);

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PLATFORM_INSERT) < 0) {
        mdebug1("at wdb_mitre_platform_insert(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PLATFORM_INSERT];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);
    sqlite3_bind_text(stmt, 2, platform, -1, NULL);

    if (wdb_step(stmt) == SQLITE_DONE) {
        w_mutex_unlock(&wdb->mutex);
        return 0;
    } else {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_attack_update(wdb_t *wdb, char *id, char *json){
    sqlite3_stmt *stmt;
    w_mutex_lock(&wdb->mutex);

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_ATTACK_UPDATE) < 0) {
        mdebug1("at wdb_mitre_attack_update(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_ATTACK_UPDATE];

    sqlite3_bind_text(stmt, 1, json, -1, NULL);
    sqlite3_bind_text(stmt, 2, id, -1,  NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        w_mutex_unlock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_attack_get(wdb_t *wdb, char *id, char *output){
    w_mutex_lock(&wdb->mutex);

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_ATTACK_GET) < 0) {
        mdebug1("at wdb_mitre_attack_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_ATTACK_GET];
    
    sqlite3_bind_text(stmt, 1, id, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 0));
        w_mutex_unlock(&wdb->mutex);
        return 1;       
        break;
    case SQLITE_DONE:
        w_mutex_unlock(&wdb->mutex);
        return 0;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_phases_get(wdb_t *wdb, char *phase_name, char *output){
    w_mutex_lock(&wdb->mutex);

    sqlite3_stmt *stmt = NULL;

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PHASE_GET) < 0) {
        mdebug1("at wdb_mitre_phases_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PHASE_GET];

    sqlite3_bind_text(stmt, 1, phase_name, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 0));
        w_mutex_unlock(&wdb->mutex);
        return 1;       
        break;
    case SQLITE_DONE:
        w_mutex_unlock(&wdb->mutex);
        return 0;
        break;
    default:
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_platforms_get(wdb_t *wdb, char *platform_name, char *output){
    w_mutex_lock(&wdb->mutex);

    sqlite3_stmt *stmt = NULL;
    w_mutex_lock(&wdb->mutex);

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PLATFORM_GET) < 0) {
        mdebug1("at wdb_mitre_phases_get(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PLATFORM_GET];

    sqlite3_bind_text(stmt, 1, platform_name, -1, NULL);

    switch (wdb_step(stmt)) {
    case SQLITE_ROW:
        snprintf(output, OS_MAXSTR - WDB_RESPONSE_BEGIN_SIZE, "%s", sqlite3_column_text(stmt, 0));
        w_mutex_unlock(&wdb->mutex);
        return 1;         
        break;
    case SQLITE_DONE:
        w_mutex_unlock(&wdb->mutex);
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
    w_mutex_lock(&wdb->mutex);
    
    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_ATTACK_DELETE) < 0) {
        mdebug1("at wdb_mitre_attack_delete(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_ATTACK_DELETE];

    sqlite3_bind_text(stmt, 1, id, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        w_mutex_unlock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_phase_delete(wdb_t *wdb, char *attack_id){
    sqlite3_stmt *stmt;
    w_mutex_lock(&wdb->mutex);

   if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PHASE_DELETE) < 0) {
        mdebug1("at wdb_mitre_phase_delete(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PHASE_DELETE];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        w_mutex_unlock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

int wdb_mitre_platform_delete(wdb_t *wdb, char *attack_id){
    sqlite3_stmt *stmt;
    w_mutex_lock(&wdb->mutex);

    if (wdb_stmt_cache(wdb, WDB_STMT_MITRE_PLATFORM_DELETE) < 0) {
        mdebug1("at wdb_mitre_phase_delete(): cannot cache statement");
        return -1;
    }
    stmt = wdb->stmt[WDB_STMT_MITRE_PLATFORM_DELETE];

    sqlite3_bind_text(stmt, 1, attack_id, -1, NULL);

    if (sqlite3_step(stmt) == SQLITE_DONE) {
        w_mutex_unlock(&wdb->mutex);
        return 0;
    } else {
        merror("sqlite3_step(): %s", sqlite3_errmsg(wdb->db));
        w_mutex_unlock(&wdb->mutex);
        return -1;
    }
}

void wdb_mitre_load(wdb_t *wdb){
    size_t n;
    int check;
    size_t size;
    char * buffer = NULL;
    FILE *fp;
    cJSON *type = NULL;
    cJSON *source_name = NULL;
    cJSON *ext_id = NULL;
    cJSON *object = NULL;
    cJSON *objects = NULL;
    cJSON *reference = NULL;
    cJSON *references = NULL;
    cJSON *kill_chain_phases = NULL;
    cJSON *kill_chain_phase = NULL;
    cJSON *chain_phase = NULL;
    cJSON *platforms = NULL;
    cJSON *platform = NULL;

    /* Load Json File */
    /* Reading enterprise-attack json file */
    fp = fopen("../ruleset/mitre/enterprise-attack.json", "r");

    if(!fp)
    {
        merror("Error at wdb_mitre_load() function. Mitre Json File not found");
        exit(1);
    }

    /* Size of the json file */
    size = get_fp_size(fp); 
    if (size > JSON_MAX_FSIZE){
        merror("Cannot load Mitre JSON file, it exceeds the size");
        exit(1);
    }

    /* Allocate memory */
    os_malloc(size+1,buffer);
    
    /* String JSON */
    n = fread(buffer, 1, size, fp);
    fclose(fp);
    
    /* Added \0 */
    if (n == size)
        buffer[size] = '\0';

    /* First, parse the whole thing */
    cJSON *root = cJSON_Parse(buffer);
    free(buffer);

    if(root == NULL){
        minfo("Mitre JSON file is empty.");
    } else {
        objects = cJSON_GetObjectItem(root, "objects");
        cJSON_ArrayForEach(object, objects){
            type = cJSON_GetObjectItem(object, "type");
            if (strcmp(type->valuestring,"attack-pattern") == 0){
                references = cJSON_GetObjectItem(object, "external_references");
                cJSON_ArrayForEach(reference, references){
                    if (cJSON_GetObjectItem(reference, "source_name") && cJSON_GetObjectItem(reference, "external_id")){
                        source_name = cJSON_GetObjectItem(reference, "source_name");
                        if (strcmp(source_name->valuestring, "mitre-attack") == 0){
                            /* All the conditions have been met */
                            /* Storing the item 'external_id' */
                            ext_id = cJSON_GetObjectItem(reference, "external_id");

                            // /* Insert functions */
                            if(wdb_mitre_attack_insert(db_global, ext_id->valuestring, cJSON_Print(object)) < 0){
                                 merror("SQLite - Mitre: object was not inserted in attack table");
                                 goto end;
                            }

                            /* Storing the item 'phase_name' of 'kill_chain_phases' */
                            kill_chain_phases = cJSON_GetObjectItem(object, "kill_chain_phases");
                            cJSON_ArrayForEach(kill_chain_phase, kill_chain_phases){
                                cJSON_ArrayForEach(chain_phase, kill_chain_phase){
                                    if(strcmp(chain_phase->string,"phase_name") == 0){
                                        /* Insert mitre phases */
                                        if(wdb_mitre_phase_insert(db_global, ext_id->valuestring, chain_phase->valuestring) < 0){
                                            merror("SQLite - Mitre: phase was not inserted in phases table");
                                            goto end;
                                        }
                                    }
                                }  
                            }

                            /* Storing the item 'x_mitre_platforms' */
                            platforms = cJSON_GetObjectItem(object, "x_mitre_platforms");
                            cJSON_ArrayForEach(platform, platforms){
                                /* Insert mitre platforms */
                                if(wdb_mitre_platform_insert(db_global, ext_id->valuestring, platform->valuestring) < 0){
                                    merror("SQLite - Mitre: platform was not inserted in platforms table");
                                    goto end;
                                }
                            }
                        }
                    }    
                }
            }
        }
    }
    cJSON_Delete(root);
end:
    exit(1);
}

