/*
 * Wazuh-DB settings manager
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WAZUH_DB_CONFIG_H
#define WAZUH_DB_CONFIG_H

/**
 * @brief This method will read the nodes of the main configuration block "wdb".
 *
 * @param xml The configuration file to read.
 * @param chld_node The "wdb" configuration block.
 * @return int OS_SUCCESS if the configuration was read with no errors, OS_INVALID otherwise.
 */
int Read_WazuhDB(const OS_XML *xml, XML_NODE chld_node);

/**
 * @brief This method will read the "backup" configuration block of Wazuh-DB.
 *
 * @param xml The configuration file to read.
 * @param node The "backup" configuration block.
 * @param BACKUP_NODE A valid configuration node declared in the enumeration wdb_backup_db.
 * @return int OS_SUCCESS if the configuration was read with no errors, OS_INVALID otherwise.
 */
int Read_WazuhDB_Backup(const OS_XML *xml, xml_node * node, int const BACKUP_NODE);

/**
 * @brief Allocates the memory for all the configuration nodes declared in wdb_backup_db and sets the default
 *        values for all the settings.
 */
void wdb_init_conf();

/**
 * @brief Frees all the allocated memory for the configuration nodes declared in wdb_backup_db.
 */
void wdb_free_conf();

#endif
