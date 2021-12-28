/*
 * Wazuh-DB settings manager
 * Copyright (C) 2015-2022, Wazuh Inc.
 * Dec 17, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WAZUH_DB_CONFIG_H
#define WAZUH_DB_CONFIG_H

int Read_WazuhDB(const OS_XML *xml, XML_NODE chld_node);
int Read_WazuhDB_Backup(const OS_XML *xml, xml_node * node, int const BACKUP_NODE);
void wdb_init_conf();
void wdb_free_conf();

#endif
