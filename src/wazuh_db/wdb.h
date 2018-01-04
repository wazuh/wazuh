/*
 * Wazuh SQLite integration
 * Copyright (C) 2016 Wazuh Inc.
 * June 06, 2016.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_H
#define WDB_H

#include "external/sqlite/sqlite3.h"
#include "syscheck_op.h"
#include "rootcheck_op.h"

#define WDB_AGENT_EMPTY 0
#define WDB_AGENT_PENDING 1
#define WDB_AGENT_UPDATED 2

#define WDB_FILE_TYPE_FILE 0
#define WDB_FILE_TYPE_REGISTRY 1

#define WDB_FIM_NOT_FOUND 0
#define WDB_FIM_ADDED 1
#define WDB_FIM_MODIFIED 2
#define WDB_FIM_READDED 3
#define WDB_FIM_DELETED 4

#define WDB_SYSCHECK 0
#define WDB_SYSCHECK_REGISTRY 1
#define WDB_ROOTCHECK 2
#define WDB_AGENTINFO 3
#define WDB_GROUPS 4
#define WDB_SYSCOLLECTOR 5

#define WDB_NETINFO_IPV4 0
#define WDB_NETINFO_IPV6 1

/* Global SQLite database */
extern sqlite3 *wdb_global;

extern char *schema_global_sql;
extern char *schema_agents_sql;

/* Open global database. Returns 0 on success or -1 on failure. */
int wdb_open_global();

/* Close global database */
void wdb_close_global();

/* Open database for agent */
sqlite3* wdb_open_agent(int id_agent, const char *name);

/* Get the file offset. Returns -1 on error or NULL. */
long wdb_get_agent_offset(int id_agent, int type);

/* Set the file offset. Returns number of affected rows, or -1 on failure. */
int wdb_set_agent_offset(int id_agent, int type, long offset);

/* Set agent updating status. Returns WDB_AGENT_*, or -1 on error. */
int wdb_get_agent_status(int id_agent);

/* Set agent updating status. Returns number of affected rows, or -1 on error. */
int wdb_set_agent_status(int id_agent, int status);

/* Get agent name from location string */
char* wdb_agent_loc2name(const char *location);

/* Find file: returns ID, or 0 if it doesn't exists, or -1 on error. */
int wdb_find_file(sqlite3 *db, const char *path, int type);

/* Find file, Returns ID, or -1 on error. */
int wdb_insert_file(sqlite3 *db, const char *path, int type);

/* Get last event from file: returns WDB_FIM_*, or -1 on error. */
int wdb_get_last_fim(sqlite3 *db, const char *path, int type);

/* Insert FIM entry. Returns ID, or -1 on error. */
int wdb_insert_fim(sqlite3 *db, int type, long timestamp, const char *f_name, const char *event, const sk_sum_t *sum);

/* Insert policy monitoring entry. Returns ID on success or -1 on error. */
int wdb_insert_pm(sqlite3 *db, const rk_event_t *event);

/* Update policy monitoring last date. Returns number of affected rows on success or -1 on error. */
int wdb_update_pm(sqlite3 *db, const rk_event_t *event);

/* Insert agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_insert_agent(int id, const char *name, const char *ip, const char *key, const char *group);

/* Update agent name. It doesn't rename agent DB file. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_update_agent_name(int id, const char *name);

/* Update agent version. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_version(int id, const char *os_name, const char *os_version, const char *os_major, const char *os_minor, const char *os_codename, const char *os_platform, const char *os_build, const char *os_uname, const char *version, const char *config_sum, const char *merged_sum, const char *manager_host, const char *node_name);

/* Update agent's last keepalive. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_keepalive(int id, long keepalive);

/* Update agent group. It opens and closes the DB. Returns number of affected rows or -1 on error. */
int wdb_update_agent_group(int id, const char *group);

/* Delete agent. It opens and closes the DB. Returns 0 on success or -1 on error. */
int wdb_remove_agent(int id);

/* Get name from agent. The string must be freed after using. Returns NULL on error. */
char* wdb_agent_name(int id);

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_create_agent_db(int id, const char *name);

/* Create database for agent from profile. Returns 0 on success or -1 on error. */
int wdb_remove_agent_db(int id);

/* Prepare SQL query with availability waiting */
int wdb_prepare(sqlite3 *db, const char *zSql, int nByte, sqlite3_stmt **stmt, const char **pzTail);

/* Execute statement with availability waiting */
int wdb_step(sqlite3_stmt *stmt);

/* Begin transaction */
int wdb_begin(sqlite3 *db);

/* Commit transaction */
int wdb_commit(sqlite3 *db);

/* Create global database */
int wdb_create_global(const char *path);

/* Create profile database */
int wdb_create_profile(const char *path);

/* Create new database file from SQL script */
int wdb_create_file(const char *path, const char *source);

/* Get an array containing the ID of every agent (except 0), ended with -1 */
int* wdb_get_all_agents();

/* Find agent by name and address. Returns ID if success or -1 on failure. */
int wdb_find_agent(const char *name, const char *ip);

/* Delete FIM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_delete_fim(int id);

/* Delete FIM events of all agents. */
void wdb_delete_fim_all();

/* Delete PM events of an agent. Returns number of affected rows on success or -1 on error. */
int wdb_delete_pm(int id);

/* Delete PM events of all agents */
void wdb_delete_pm_all();

/* Rebuild database. Returns 0 on success or -1 on error. */
int wdb_vacuum(sqlite3 *db);

/* Insert key-value pair into info table */
int wdb_insert_info(const char *key, const char *value);

// Insert network tuple. Return ID on success or -1 on error.
int wdb_insert_net_iface(sqlite3 * db, const char * name, const char * adapter, const char * type, const char * state, int mtu, const char * mac, long tx_packets, long rx_packets, long tx_bytes, long rx_bytes);

// Insert network address tuple. Return ID on success or -1 on error.
int wdb_insert_net_addr(sqlite3 * db, const char * name, int type, const char * address, const char * netmask, const char * broadcast, const char * gateway, const char * dhcp);

// Clean network tables. Return number of affected rows on success or -1 on error.
int wdb_delete_network(sqlite3 * db);

// Insert OS info tuple. Return ID on success or -1 on error.
int wdb_insert_osinfo(sqlite3 * db, const char * os_name, const char * os_version, const char * node_name, const char * machine, const char * os_major, const char * os_minor, const char * os_build, const char * os_platform, const char * sysname, const char * release, const char * version);

// Clean OS info table. Return number of affected rows on success or -1 on error.
int wdb_delete_osinfo(sqlite3 * db);

// Insert hardware info tuple. Return id on success or -1 on error.
int wdb_insert_hwinfo(sqlite3 * db, const char * board_serial, const char * cpu_name, int cpu_cores, double cpu_mhz, long ram_total, long ram_free);

// Clean hardware info table. Return number of affected rows on success or -1 on error.
int wdb_delete_hwinfo(sqlite3 * db);

#endif
