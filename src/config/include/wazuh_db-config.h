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



#ifndef CLIENT
struct cJSON;
/**
 * @brief Reader of the `wdb` section of the effective YAML document (etc/wazuh-manager.yml, see mconf-config.h).
 *
 * @param wdb The section returned by w_mconf_section("wdb"); NULL or an absent backup block keeps the defaults.
 * @return OS_SUCCESS, or OS_INVALID when a value breaks the rules the schema cannot express.
 */
int Read_WazuhDB_JSON(const struct cJSON *wdb);
#endif

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
