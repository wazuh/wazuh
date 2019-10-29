/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "dbd-config.h"
#include "config.h"


int Read_DB(XML_NODE node, __attribute__((unused)) void *config1, void *config2, char **output)
{
    int i = 0;
    DBConfig *db_config;
    char message[OS_FLSIZE];

    /* XML definitions */
    const char *xml_dbhost = "hostname";
    const char *xml_dbuser = "username";
    const char *xml_dbpass = "password";
    const char *xml_dbdb = "database";
    const char *xml_dbport = "port";
    const char *xml_dbsock = "socket";
    const char *xml_dbtype = "type";

    db_config = (DBConfig *)config2;
    if (!db_config) {
        return (0);
    }

    /* Read the xml */
    while (node[i]) {
        if (!node[i]->element) {
            if (output == NULL){
                merror(XML_ELEMNULL);
            } else {
                wm_strcat(output, "Invalid NULL element in the configuration.", '\n');
            }
            return (OS_INVALID);
        } else if (!node[i]->content) {
            if (output == NULL){
                merror(XML_VALUENULL, node[i]->element);
            } else {
                snprintf(message, OS_FLSIZE,
                        "Invalid NULL content for element: '%s'.",
                        node[i]->element);
                wm_strcat(output, message, '\n');
            }
            return (OS_INVALID);
        }
        /* Mail notification */
        else if (strcmp(node[i]->element, xml_dbhost) == 0) {
            if (db_config->host) {
                free(db_config->host);
            }
            os_strdup(node[i]->content, db_config->host);
        } else if (strcmp(node[i]->element, xml_dbuser) == 0) {
            if (db_config->user) {
                free(db_config->user);
            }
            os_strdup(node[i]->content, db_config->user);
        } else if (strcmp(node[i]->element, xml_dbpass) == 0) {
            if (db_config->pass) {
                free(db_config->pass);
            }
            os_strdup(node[i]->content, db_config->pass);
        } else if (strcmp(node[i]->element, xml_dbdb) == 0) {
            if (db_config->db) {
                free(db_config->db);
            }
            os_strdup(node[i]->content, db_config->db);
        } else if (strcmp(node[i]->element, xml_dbport) == 0) {
            db_config->port = (unsigned int) atoi(node[i]->content);
        } else if (strcmp(node[i]->element, xml_dbsock) == 0) {
            os_strdup(node[i]->content, db_config->sock);
        } else if (strcmp(node[i]->element, xml_dbtype) == 0) {
            if (strcmp(node[i]->content, "mysql") == 0) {
                db_config->db_type = MYSQLDB;
            } else if (strcmp(node[i]->content, "postgresql") == 0) {
                db_config->db_type = POSTGDB;
            } else if (output == NULL) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            } else {
                snprintf(message, OS_FLSIZE,
                        "Invalid value for element '%s': %s.",
                        node[i]->element, node[i]->content);
                wm_strcat(output, message, '\n');
                return (OS_INVALID);
            }
        } else if (output == NULL) {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        } else {
            snprintf(message, OS_FLSIZE,
                        "Invalid element in the configuration: '%s'.",
                        node[i]->element);
            wm_strcat(output, message, '\n');
            return (OS_INVALID);
        }
        i++;
    }

    return (0);
}

int Test_DBD(const char *path, char **output) {
    DBConfig *dbdConfig;
    os_calloc(1, sizeof(DBConfig), dbdConfig);

    if(ReadConfig(CDBD, path, NULL, dbdConfig, output) < 0) {
        if (output == NULL){
            merror(CONF_READ_ERROR, "Database");
        } else {
            wm_strcat(output, "ERROR: Invalid configuration in Database", '\n');
        }
		goto fail;
    }

    /* Check if dbd isn't supposed to run */
    if (!dbdConfig->host &&
            !dbdConfig->user &&
            !dbdConfig->pass &&
            !dbdConfig->db &&
            !dbdConfig->sock &&
            !dbdConfig->port &&
            !dbdConfig->db_type) {
        free_dbdConfig(dbdConfig);
        return 0;
    }

        /* Check for a valid config */
    if (!dbdConfig->host ||
            !dbdConfig->user ||
            !dbdConfig->pass ||
            !dbdConfig->db ||
            !dbdConfig->db_type) {
        if (output == NULL){
            merror(DB_MISS_CONFIG);
        } else {
            wm_strcat(output, "ERROR: Invalid configuration in Database", '\n');
        }
        goto fail;
    }

    /* Check for config errors */
    if (dbdConfig->db_type != MYSQLDB) {
#ifndef MYSQL_DATABASE_ENABLED
        if (output == NULL){
            merror(DB_COMPILED, "mysql");
        } else {
            wm_strcat(output, "ERROR: Invalid configuration in Database", '\n');
        }
        goto fail;
#endif
    } else if (dbdConfig->db_type == POSTGDB) {
#ifndef PGSQL_DATABASE_ENABLED
        if (output){
            merror(DB_COMPILED, "postgresql");
        } else {
            wm_strcat(output, "ERROR: Invalid configuration in Database", '\n');
        }
        goto fail;
#endif
    }

    free_dbdConfig(dbdConfig);
    return 0;

fail:
    // Free Memory
    free_dbdConfig(dbdConfig);
    return OS_INVALID;
}

void free_dbdConfig(DBConfig * db_config) {
    if(db_config) {
        os_free(db_config->host);
        os_free(db_config->user);
        os_free(db_config->pass);
        os_free(db_config->db);
        os_free(db_config->sock);
        os_free(db_config->conn);
        os_free(db_config->location_hash);
        if(db_config->includes) {
            int i = 0;
            while(db_config->includes[i]) {
                os_free(db_config->includes[i]);
                i++;
            }
            os_free(db_config->includes);
        }
        os_free(db_config);
    }
}
