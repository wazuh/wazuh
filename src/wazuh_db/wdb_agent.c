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

static const char *global_db_queries[] = {
    [SQL_INSERT_AGENT] = "global sql INSERT INTO agent (id, name, ip, register_ip, internal_key, date_add, `group`) VALUES (%d, '%s', '%s', '%s', '%s', %lu, '%s');",
    [SQL_UPDATE_AGENT_NAME] = "global sql UPDATE agent SET name = '%s' WHERE id = %d;",
    [SQL_UPDATE_AGENT_VERSION] = "global sql UPDATE agent SET os_name = '%s', os_version = '%s', os_major = '%s', os_minor = '%s', os_codename = '%s', os_platform = '%s', os_build = '%s', os_uname = '%s', os_arch = '%s', version = '%s', config_sum = '%s', merged_sum = '%s', manager_host = '%s', node_name = '%s' WHERE id = %d;",
    [SQL_UPDATE_AGENT_VERSION_IP] = "global sql UPDATE agent SET os_name = '%s', os_version = '%s', os_major = '%s', os_minor = '%s', os_codename = '%s', os_platform = '%s', os_build = '%s', os_uname = '%s', os_arch = '%s', version = '%s', config_sum = '%s', merged_sum = '%s', manager_host = '%s', node_name = '%s' , ip = '%s' WHERE id = %d;",
    [SQL_UPDATE_AGENT_KEEPALIVE] = "global sql UPDATE agent SET last_keepalive = %lu WHERE id = %d;",
    [SQL_DELETE_AGENT] = "global sql DELETE FROM agent WHERE id = %d;",
    [SQL_SELECT_AGENT] = "global sql SELECT name FROM agent WHERE id = %d;",
    [SQL_SELECT_AGENT_GROUP] = "global sql SELECT `group` FROM agent WHERE id = %d;",
    [SQL_SELECT_AGENTS] = "global sql SELECT id FROM agent WHERE id != 0;",
    [SQL_FIND_AGENT] = "global sql SELECT id FROM agent WHERE name = '%s' AND (register_ip = '%s' OR register_ip LIKE '%s' || '/_%');",
    [SQL_SELECT_FIM_OFFSET] = "global sql SELECT fim_offset FROM agent WHERE id = %d;",
    [SQL_SELECT_REG_OFFSET] = "global sql SELECT reg_offset FROM agent WHERE id = %d;",
    [SQL_UPDATE_FIM_OFFSET] = "global sql UPDATE agent SET fim_offset = %lu WHERE id = %d;",
    [SQL_UPDATE_REG_OFFSET] = "globL sql UPDATE agent SET reg_offset = %lu WHERE id = %d;",
    [SQL_SELECT_AGENT_STATUS] = "global sql SELECT status FROM agent WHERE id = %d;",
    [SQL_UPDATE_AGENT_STATUS] = "global sql UPDATE agent SET status = '%s' WHERE id = %d;",
    [SQL_UPDATE_AGENT_GROUP] = "global sql UPDATE agent SET `group` = '%s' WHERE id = %d;",
    [SQL_FIND_GROUP] = "global sql SELECT id FROM `group` WHERE name = '%s';",
    [SQL_INSERT_AGENT_GROUP] = "global sql INSERT INTO `group` (name) VALUES('%s');",
    [SQL_INSERT_AGENT_BELONG] = "global sql INSERT INTO belongs (id_group, id_agent) VALUES(%d, %d);",
    [SQL_DELETE_AGENT_BELONG] = "global sql DELETE FROM belongs WHERE id_agent = %d",
    [SQL_DELETE_GROUP_BELONG] = "global sql DELETE FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = '%s' );", 
    [SQL_DELETE_GROUP] = "global sql DELETE FROM `group` WHERE name = '%s';",
 };

//static const char *SQL_INSERT_AGENT = "INSERT INTO agent (id, name, ip, register_ip, internal_key, date_add, `group`) VALUES (?, ?, ?, ?, ?, ?, ?);";
//static const char *SQL_UPDATE_AGENT_NAME = "UPDATE agent SET name = ? WHERE id = ?;";
//static const char *SQL_UPDATE_AGENT_VERSION = "UPDATE agent SET os_name = ?, os_version = ?, os_major = ?, os_minor = ?, os_codename = ?, os_platform = ?, os_build = ?, os_uname = ?, os_arch = ?, version = ?, config_sum = ?, merged_sum = ?, manager_host = ?, node_name = ? WHERE id = ?;";
//static const char *SQL_UPDATE_AGENT_VERSION_IP = "UPDATE agent SET os_name = ?, os_version = ?, os_major = ?, os_minor = ?, os_codename = ?, os_platform = ?, os_build = ?, os_uname = ?, os_arch = ?, version = ?, config_sum = ?, merged_sum = ?, manager_host = ?, node_name = ? , ip = ? WHERE id = ?;";
//static const char *SQL_UPDATE_AGENT_KEEPALIVE = "UPDATE agent SET last_keepalive = ? WHERE id = ?;";
//static const char *SQL_SELECT_AGENT_STATUS = "SELECT status FROM agent WHERE id = ?;";
//static const char *SQL_UPDATE_AGENT_STATUS = "UPDATE agent SET status = ? WHERE id = ?;";
//static const char *SQL_UPDATE_AGENT_GROUP = "UPDATE agent SET `group` = ? WHERE id = ?;";
//static const char *SQL_INSERT_AGENT_GROUP = "INSERT INTO `group` (name) VALUES(?)";
//static const char *SQL_SELECT_AGENT_GROUP = "SELECT `group` FROM agent WHERE id = ?;";
//static const char *SQL_INSERT_AGENT_BELONG = "INSERT INTO belongs (id_group, id_agent) VALUES(?, ?)";
//static const char *SQL_DELETE_AGENT_BELONG = "DELETE FROM belongs WHERE id_agent = ?";
//static const char *SQL_DELETE_GROUP_BELONG = "DELETE FROM belongs WHERE id_group = (SELECT id FROM 'group' WHERE name = ? );";
//static const char *SQL_SELECT_FIM_OFFSET = "SELECT fim_offset FROM agent WHERE id = ?;";
//static const char *SQL_SELECT_REG_OFFSET = "SELECT reg_offset FROM agent WHERE id = ?;";
//static const char *SQL_UPDATE_FIM_OFFSET = "UPDATE agent SET fim_offset = ? WHERE id = ?;";
//static const char *SQL_UPDATE_REG_OFFSET = "UPDATE agent SET reg_offset = ? WHERE id = ?;";
//static const char *SQL_DELETE_AGENT = "DELETE FROM agent WHERE id = ?;";
//static const char *SQL_SELECT_AGENT = "SELECT name FROM agent WHERE id = ?;";
//static const char *SQL_SELECT_AGENTS = "SELECT id FROM agent WHERE id != 0;";
//static const char *SQL_FIND_AGENT = "SELECT id FROM agent WHERE name = ? AND (register_ip = ? OR register_ip LIKE ?2 || '/_%');";
//static const char *SQL_FIND_GROUP = "SELECT id FROM `group` WHERE name = ?;"; 
static const char *SQL_SELECT_GROUPS = "SELECT name FROM `group`;";
//static const char *SQL_DELETE_GROUP = "DELETE FROM `group` WHERE name = ?;";

/* Insert agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_insert_agent(int id, const char *name, const char *ip, const char *register_ip, const char *key, const char *group, int keep_date) {
    int result = 0;
    time_t date = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    if(keep_date) {
        date = get_agent_date_added(id);
    } else {
        time(&date);
    }

    // If the strings are empty, insert NULL
    if (!ip){
        ip=NULL;
    }

    if(!register_ip){
        register_ip=NULL;
    }

    if (!key)
        key=NULL;
    
    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_INSERT_AGENT], id, name, ip, register_ip, key, date, group);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if( result == 0 ){
        result = wdb_create_agent_db(id, name);
    } else {
        mdebug1("GLobal DB Cannot execute SQL query; err database %s/%s.db", WDB2_DIR, WDB2_GLOB_NAME);
        mdebug2("Global DB SQL query: %s", wdbquery);
        result = -1;
    }

    return result;
}

/* Update agent name. It doesn't rename agent DB file. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_name(int id, const char *name) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_UPDATE_AGENT_NAME], name, id);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

    return result == 0 ? 0 : -1;
}

/* Update agent version. It opens and closes the DB. Returns 1 or -1 on error. */
int wdb_update_agent_version(int id, const char *os_name, const char *os_version, const char *os_major, const char *os_minor, const char *os_codename, const char *os_platform, const char *os_build, const char *os_uname, const char *os_arch, const char *version, const char *config_sum, const char *merged_sum, const char *manager_host, const char *node_name, const char *agent_ip) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;
  
    if(agent_ip) {
        snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_UPDATE_AGENT_VERSION_IP], os_name, os_version, os_major, os_minor,os_codename, os_platform, os_build, os_uname, os_arch, version, config_sum,merged_sum, manager_host, node_name, agent_ip , id );
    } else {
        snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_UPDATE_AGENT_VERSION],  os_name, os_version, os_major, os_minor,os_codename, os_platform, os_build, os_uname, os_arch, version, config_sum,merged_sum, manager_host, node_name , id );
    }

    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));
    return result == 0 ? 1 : -1;
}

/* Update agent's last keepalive time. It opens and closes the DB. Returns 1 or -1 on error. */
int wdb_update_agent_keepalive(int id, long keepalive) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_UPDATE_AGENT_KEEPALIVE], keepalive, id);
    
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));
    return result == 0 ? 1 : -1;
}

/* Delete agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_agent(int id) {
    int result = 0 ;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;
    char * name = "";

    name = wdb_agent_name(id);
    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_DELETE_AGENT], id);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput)) == 0;
    wdb_delete_agent_belongs(id);

    result = result && name ? wdb_remove_agent_db(id, name) : -1;

    os_free(name);
    return result;
}

/* Get name from agent. The string must be freed after using. Returns NULL on error. */
char* wdb_agent_name(int id) {
    char *result = NULL;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_SELECT_AGENT], id);

    switch (wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput))) {
    case 0:
        os_strdup(wdboutput,result);
        break;
    default:
        mdebug1("SQLite error. Query: %s", wdbquery);
        result = NULL;
    }

    return result;
}

/* Get group from agent. The string must be freed after using. Returns NULL on error. */
char* wdb_agent_group(int id) {
    char *result = NULL;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_SELECT_AGENT_GROUP], id);

    switch (wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput))) {
    case 0:
        os_strdup(wdboutput,result);
        break;
    default:
        mdebug1("SQLite error. Query: %s", wdbquery);
        result = NULL;
    }

    return result;
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
    if (fclose(dest) == -1) {
        merror("Couldn't write/close file %s completely ", path);
        return -1;
    }

    if (result < 0)
        return -1;

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
    int i = 0;
    int n = 0;
    int *array = NULL;
    char *json_string = NULL;
    cJSON *elem = NULL;
    cJSON *name = NULL;
    cJSON *root = NULL;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE,"%s", global_db_queries[SQL_SELECT_AGENTS]);
    wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if(json_string = wstr_chr(wdboutput, ' '), json_string ){
        *json_string='\0';
        json_string++;

    } else{
        mdebug1("SQLite result has no space. Query: %s",wdbquery);
        os_free(array);
        return NULL;
    }

    if(strcmp(wdboutput,"ok") == 0 && strcmp(json_string,"[]") != 0){
        root = cJSON_Parse(json_string);
        n = cJSON_GetArraySize(root);
        os_calloc(n+1, sizeof(int),array);        
        
        for (i = 0; i < n; i++) {
            elem = cJSON_GetArrayItem(root, i);
            name = cJSON_GetObjectItem(elem, "id");
            array[i]=name->valueint;
            }
        array[i] = -1;

    } else{
        mdebug1("SQLite Query failed: %s", wdbquery);
        os_free(array);
        return NULL;
    }

    return array;
}

/* Find agent by name and address. Returns id if success, -1 on failure */
int wdb_find_agent(const char *name, const char *ip) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;
    char *json_string = NULL;
    cJSON *root = NULL;
    cJSON *elem = NULL;
    cJSON *json_name = NULL;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_FIND_AGENT], name, ip, ip);
    wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if(json_string = wstr_chr(wdboutput, ' '), json_string ){
        *json_string='\0';
        json_string++;
    } else{
        mdebug1("SQLite result has no space. Query: %s",wdbquery);
        return -1;
    }

    if(strcmp(wdboutput,"ok") == 0 && strcmp(json_string,"[]") != 0){
        root = cJSON_Parse(json_string);    
        elem = cJSON_GetArrayItem(root, 0);
        json_name = cJSON_GetObjectItem(elem, "id");
        result = json_name->valueint;
    } else{
        mdebug1("SQLite Query failed: %s", wdbquery);
        return -1;
    }
        
    return result;
}

/* Get the file offset. Returns -1 on error or NULL. */
long wdb_get_agent_offset(int id_agent, int type) {
    long int result = 0;
    bool is_FIM = FALSE;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;
    char *json_string = NULL;
    cJSON *root = NULL;
    cJSON *elem = NULL;
    cJSON *json_name = NULL;

    switch (type) {
    case WDB_SYSCHECK:
        snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_SELECT_FIM_OFFSET], id_agent);
        is_FIM = TRUE;
        break;
    case WDB_SYSCHECK_REGISTRY:
        snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_SELECT_REG_OFFSET],id_agent);
        is_FIM = FALSE;
        break;
    default:
        return -1;
    }

    wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));
 
    if(json_string = wstr_chr(wdboutput, ' '), json_string ){
        *json_string='\0';
        json_string++;
    } else{
        mdebug1("SQLite result has no space. Query: %s",wdbquery);
        return -1;
    }

    if(strcmp(wdboutput,"ok") == 0 && strcmp(json_string,"[]") != 0){
        root = cJSON_Parse(json_string);    
        elem = cJSON_GetArrayItem(root, 0);
        json_name = is_FIM == TRUE ? cJSON_GetObjectItem(elem, "fim_offset") : cJSON_GetObjectItem(elem, "reg_offset");
        result = json_name->valueint;
    } else{
        mdebug1("SQLite Query failed: %s", wdbquery);
        return -1;
    }

    return result;
}

/* Set the file offset. Returns 1, or -1 on failure. */
int wdb_set_agent_offset(int id_agent, int type, long offset) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    switch (type) {
    case WDB_SYSCHECK:
        snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_UPDATE_FIM_OFFSET], offset, id_agent);
        break;
    case WDB_SYSCHECK_REGISTRY:
        snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_UPDATE_REG_OFFSET], offset, id_agent);
        break;
    default:
        return -1;
    }

    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));
    return result == 0 ? 1 : -1;
}

/* Set agent updating status. Returns WDB_AGENT_*, or -1 on error. */
int wdb_get_agent_status(int id_agent) {
    int result = 0;
    const char *status = NULL;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;
    char *json_string = NULL;
    cJSON *root = NULL;
    cJSON *elem = NULL;
    cJSON *json_name = NULL;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_SELECT_AGENT_STATUS], id_agent);
    wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if(json_string = wstr_chr(wdboutput, ' '), json_string ){
        *json_string='\0';
        json_string++;
    } else{
        mdebug1("SQLite result has no space. Query: %s",wdbquery);
        return -1;
    }

    if(strcmp(wdboutput,"ok") == 0 && strcmp(json_string,"[]") != 0 ){
        root = cJSON_Parse(json_string);    
        elem = cJSON_GetArrayItem(root, 0);
        json_name = cJSON_GetObjectItem(elem, "status");
        status = json_name->valuestring;
        result = !strcmp(status, "empty") ? WDB_AGENT_EMPTY : !strcmp(status, "pending") ? WDB_AGENT_PENDING : WDB_AGENT_UPDATED;
    } else{
        mdebug1("SQLite Query failed: %s", wdbquery);
        return -1;
    }
     
    return result;
}

/* Set agent updating status. Returns 1, or -1 on error. */
int wdb_set_agent_status(int id_agent, int status) {
    int result = 0;
    const char *str_status = NULL;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;
 
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
        return -1;
    }

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_UPDATE_AGENT_STATUS], str_status, id_agent);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

    return result == 0 ? 1 : -1;
}

/* Update agent group. It opens and closes the DB. Returns 1 or -1 on error. */
int wdb_update_agent_group(int id, char *group) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_UPDATE_AGENT_GROUP], group, id);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if(wdb_update_agent_multi_group(id,group) < 0){
        return -1;
    }

    return result;
}

/* Update agent multi group. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_multi_group(int id, char *group) {
    int result = 0;

    /* Wipe out the agent multi groups relation for this agent */
    if (wdb_delete_agent_belongs(id) < 0) {
        return -1;
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

            while( multi_group != NULL ) {

                /* Update de groups table */
                int id_group = wdb_find_group(multi_group);

                if(id_group <= 0){
                    id_group = wdb_insert_group(multi_group);
                }

                if (wdb_update_agent_belongs(id_group,id) < 0){
                    return -1;
                }

                multi_group = strtok_r(NULL, delim, &save_ptr);
            }
        } else {

            /* Update de groups table */
            int id_group = wdb_find_group(group);

            if(id_group <= 0){
                id_group = wdb_insert_group(group);
            }

            if ( wdb_update_agent_belongs(id_group,id) < 0){
                return -1;
            }
        }
    }

    return result;
}

/* Find group by name. Returns id if success or -1 on failure. */
int wdb_find_group(const char *name) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;
    char *json_string = NULL;
    cJSON *root = NULL;
    cJSON *elem = NULL;
    cJSON *json_name = NULL;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_FIND_GROUP], name);
    wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if(json_string = wstr_chr(wdboutput, ' '), json_string ){
        *json_string='\0';
        json_string++;
    } else{
        mdebug1("SQLite result has no space. Query: %s",wdbquery);
        return -1;
    }

    if(strcmp(wdboutput,"ok") == 0 && strcmp(json_string,"[]") != 0){
        root = cJSON_Parse(json_string);    
        elem = cJSON_GetArrayItem(root, 0);
        json_name = cJSON_GetObjectItem(elem, "id");
        result = json_name->valueint;
    } else{
        mdebug1("SQLite Query failed: %s", wdbquery);
        return -1;
    }
        
    return result;
}

/* Insert a new group. Returns id if success or -1 on failure. */
int wdb_insert_group(const char *name) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_INSERT_AGENT_GROUP], name);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));

    if (result == 0)
        result = wdb_find_group(name);
    else {
        mdebug1("SQLite query error: %s", wdbquery);
        result = -1;
    }

    return result;
}

/* Update agent belongs table. It opens and closes the DB. Returns 1 or -1 on error. */
int wdb_update_agent_belongs(int id_group, int id_agent) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_INSERT_AGENT_BELONG], id_group, id_agent);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));
  
    return result == 0 ? 1 : -1;
}

/* Delete agent belongs table. It opens and closes the DB. Returns 1 or -1 on error. */
int wdb_delete_agent_belongs(int id_agent) {
    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_DELETE_AGENT_BELONG], id_agent);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));
 
    return result == 0 ? 1 : -1;
}

int wdb_update_groups(const char *dirname) {
    int result =  0;
    int i;
    int n = 1;
    char **array;
    sqlite3_stmt *stmt = NULL;

    if (!(array = (char**) calloc(1, sizeof(char*)))) {
        merror("wdb_update_groups(): memory error");
        return -1;
    }

    if (wdb_open_global() < 0) {
        free(array);
        return -1;
    }

    if (wdb_prepare(wdb_global, SQL_SELECT_GROUPS, -1, &stmt, NULL)) {
        mdebug1("SQLite: %s", sqlite3_errmsg(wdb_global));
        wdb_close_global();
        free(array);
        return -1;
    }

    for (i = 0; wdb_step(stmt) == SQLITE_ROW; i++) {
        if (i + 1 == n) {
            char **newarray;

            if (!(newarray = (char **)realloc(array, sizeof(char *) * (n *= 2)))) {
                merror("wdb_update_groups(): memory error");
                sqlite3_finalize(stmt);
                wdb_close_global();
                free(array);
                return -1;
            }

            array = newarray;
        }
        os_strdup((char*)sqlite3_column_text(stmt, 0),array[i]);
    }

    array[i] = NULL;

    sqlite3_finalize(stmt);

    for(i=0;array[i];i++){
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
                return -1;
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
        return -1;
    }

    while ((dirent = readdir(dir))){
        if (dirent->d_name[0] != '.'){
            char path[PATH_MAX];
            snprintf(path,PATH_MAX,"%s/%s",dirname,dirent->d_name);

            if (!IsDir(path)) {
                if(wdb_find_group(dirent->d_name) <= 0){
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
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_DELETE_GROUP_BELONG], name);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));
  
    return result == 0 ? 0 : -1;
}

/* Delete group. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_group_db(const char *name) {

    if(wdb_remove_group_from_belongs_db(name) == -1){
        merror("At wdb_remove_group_from_belongs_db(): couldn't delete '%s' from 'belongs' table.", name);
        return -1;
    }

    int result = 0;
    char wdbquery[OS_BUFFER_SIZE] = "";
    char wdboutput[OS_BUFFER_SIZE] = "";
    int wdb_sock = -1;

    snprintf(wdbquery, OS_BUFFER_SIZE, global_db_queries[SQL_DELETE_GROUP], name);
    result = wdbc_query_ex(&wdb_sock, wdbquery, wdboutput, sizeof(wdboutput));
  
    return result == 0 ? 0 : -1;
}

int wdb_agent_belongs_first_time(){
    int i;
    char *group;
    int *agents;

    if ((agents = wdb_get_all_agents())) {

        for (i = 0; agents[i] != -1; i++) {
            group = wdb_agent_group(agents[i]);

            if(group){
                wdb_update_agent_multi_group(agents[i],group);
                free(group);
            }
        }
        free(agents);
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

            if (sscanf(date, "%d-%d-%d %d:%d:%d",&t.tm_year, &t.tm_mon, &t.tm_mday, &t.tm_hour, &t.tm_min, &t.tm_sec)<6) {
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
