/*
 * Wazuh DB helper module for agents database
 * Copyright (C) 2015-202, Wazuh Inc.
 * February 10, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef WDB_GLOBAL_HELPERS_H
#define WDB_GLOBAL_HELPERS_H

#include "../wdb.h"

typedef enum global_db_access {
    WDB_INSERT_AGENT,
    WDB_INSERT_AGENT_GROUP,
    WDB_INSERT_AGENT_BELONG,
    WDB_UPDATE_AGENT_NAME,
    WDB_UPDATE_AGENT_DATA,
    WDB_UPDATE_AGENT_KEEPALIVE,
    WDB_UPDATE_AGENT_CONNECTION_STATUS,
    WDB_UPDATE_AGENT_GROUP,
    WDB_SET_AGENT_LABELS,
    WDB_GET_ALL_AGENTS,
    WDB_FIND_AGENT,
    WDB_GET_AGENT_INFO,
    WDB_GET_AGENT_LABELS,
    WDB_SELECT_AGENT_NAME,
    WDB_SELECT_AGENT_GROUP,
    WDB_SELECT_KEEPALIVE,
    WDB_FIND_GROUP,
    WDB_SELECT_GROUPS,
    WDB_DELETE_AGENT,
    WDB_DELETE_GROUP,
    WDB_DELETE_AGENT_BELONG,
    WDB_DELETE_GROUP_BELONG,
    WDB_RESET_AGENTS_CONNECTION,
    WDB_GET_AGENTS_BY_CONNECTION_STATUS,
    WDB_DISCONNECT_AGENTS
} global_db_access;

/**
 * @brief Insert agent to the global.db.
 *
 * @param[in] id The agent ID.
 * @param[in] name The agent name.
 * @param[in] ip The agent ip address.
 * @param[in] register_ip The agent register IP.
 * @param[in] internal_key The client key of the agent.
 * @param[in] group The agent group.
 * @param[in] keep_date If 1, the addition date will be taken from agents-timestamp. If 0, the addition date is the current time.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_insert_agent(int id,
                     const char *name,
                     const char *ip,
                     const char *register_ip,
                     const char *internal_key,
                     const char *group,
                     int keep_date,
                     int *sock);

/**
 * @brief Insert a new group.
 *
 * @param[in] name The group name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_insert_group(const char *name, int *sock);

/**
 * @brief Update agent belongs table.
 *
 * @param[in] id_group Id of the group to be updated.
 * @param[in] id_agent Id of the agent to be updated.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_update_agent_belongs(int id_group, int id_agent, int *sock);

/**
 * @brief Update agent name in global.db.
 *
 * @param[in] id The agent ID.
 * @param[in] name The agent name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_update_agent_name(int id, const char *name, int *sock);

/**
 * @brief Update agent data in global.db.
 *
 * @param[in] agent_data A pointer to an agent_info_data structure with the agent information.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns 0 on success or -1 on error.
 */
int wdb_update_agent_data(agent_info_data *agent_data, int *sock);

/**
 * @brief Update agent's last keepalive and modifies the cluster synchronization status.
 *
 * @param[in] id Id of the agent for whom the keepalive must be updated.
 * @param[in] connection_status String with the connection status to be set.
 * @param[in] sync_status String with the cluster synchronization status to be set.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_update_agent_keepalive(int id, const char *connection_status, const char *sync_status, int *sock);

/**
 * @brief Update agent's connection status.
 *
 * @param[in] id Id of the agent for whom the connection status must be updated.
 * @param[in] connection_status String with the connection status to be set.
 * @param[in] sync_status String with the cluster synchronization status to be set.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_update_agent_connection_status(int id, const char *connection_status, const char *sync_status, int *sock);

/**
 * @brief Update agent group. If the group is not specified, it is set to NULL.
 *
 * @param[in] id ID of the agent.
 * @param[in] group The group to be set.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS if success. OS_INVALID on error.
 */
int wdb_update_agent_group(int id,char *group, int *sock);

/**
 * @brief Update agent's labels.
 *
 * @param[in] id Id of the agent for whom the labels must be updated.
 * @param[in] labels String with the key-values separated by EOL.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_set_agent_labels(int id, const char *labels, int *sock);

/**
 * @brief Returns an array containing the ID of every agent (except 0), ended with -1.
 * This method creates and sends a command to WazuhDB to receive the ID of every agent.
 * If the response is bigger than the capacity of the socket, multiple commands will be sent until every agent ID is obtained.
 * The array is heap allocated memory that must be freed by the caller.
 *
 * @param [in] include_manager flag to include the manager on agents list
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Pointer to the array, on success.
 * @retval NULL on errors.
 */
int* wdb_get_all_agents(bool include_manager, int *sock);

/**
 * @brief Find agent id by name and address.
 *
 * @param[in] name Name of the agent.
 * @param[in] ip IP address of the agent.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns id if success. OS_INVALID on error.
 */
int wdb_find_agent(const char *name, const char *ip, int *sock);

/**
 * @brief Returns a JSON with all the agent's information.
 *
 * @param[in] id Id of the agent for whom the information is requested.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return JSON* with the information on success or NULL on failure.
 */
cJSON* wdb_get_agent_info(int id, int *sock);

/**
 * @brief Returns a JSON with all the agent's labels.
 *
 * @param[in] id Id of the agent for whom the labels are requested.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return JSON* with the labels on success or NULL on failure.
 */
cJSON* wdb_get_agent_labels(int id, int *sock);

/**
 * @brief Get name from agent table in global.db by using its ID.
 *
 * @param[in] id Id of the agent that the name must be selected.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return A string with the agent name on success or NULL on failure.
 */
char* wdb_get_agent_name(int id, int *sock);

/**
 * @brief Get group from agent table in global.db by using its ID.
 *
 * @param[in] id Id of the agent that the name must be selected.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return A string with the agent group on success or NULL on failure.
 */
char* wdb_get_agent_group(int id, int *sock);

/**
 * @brief Function to get the agent last keepalive.
 *
 * @param [in] name String with the name of the agent.
 * @param [in] ip String with the ip of the agent.
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns this value, 0 on NULL or OS_INVALID on error.
 */
time_t wdb_get_agent_keepalive(const char *name, const char *ip, int *sock);

/**
 * @brief Find group by name.
 *
 * @param[in] name The group name.
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns id if success or OS_INVALID on failure.
 */
int wdb_find_group(const char *name, int *sock);

/**
 * @brief Update groups table.
 *
 * @param[in] name The groups directory.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS if success or OS_INVALID on failure.
 */
int wdb_update_groups(const char *dirname, int *sock);

/**
 * @brief Delete an agent from agent table in global.db by using its ID.
 *
 * @param[in] id Id of the agent to be deleted.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_remove_agent(int id, int *sock);

/**
 * @brief Delete group.
 *
 * @param[in] name The group name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_remove_group_db(const char *name, int *sock);

/**
 * @brief Delete an agent from belongs table in global.db by using its ID.
 *
 * @param[in] id Id of the agent to be deleted.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_delete_agent_belongs(int id, int *sock);

/**
 * @brief Delete group from belongs table.
 *
 * @param[in] name The group name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_remove_group_from_belongs_db(const char *name, int *sock);

/**
 * @brief Reset the connection_status column of every agent (excluding the manager).
 *        If connection_status is pending or connected it will be changed to disconnected.
 *        If connection_status is disconnected or never_connected it will not be changed.
 *        It also set the 'sync_status' with the specified value.
 *
 * @param[in] sync_status String with the cluster synchronization status to be set.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_reset_agents_connection(const char *sync_status, int *sock);

/**
 * @brief Returns an array containing the ID of every agent (excluding the manager) that matches
 *        the specified connection status, ended with -1.
 *        This method creates and sends a command to WazuhDB to receive the ID of every agent.
 *        If the response is bigger than the capacity of the socket, multiple commands will be sent until every
 *        agent ID is obtained. The array is heap allocated memory that must be freed by the caller.
 *
 * @param[in] connection_status The connection status.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Pointer to the array, on success. NULL on errors.
 */
int* wdb_get_agents_by_connection_status(const char* connection_status, int *sock);

/**
 * @brief Set agents as disconnected based on the keepalive and return an array containing
 * the ID of every agent that had been set as disconnected.
 * This method creates and sends a command to WazuhDB to set as disconnected all the
 * agents (excluding the manager) with a last_keepalive before the specified keepalive threshold.
 * If the response is bigger than the capacity of the socket, multiple commands will be sent until every agent is covered.
 * The array is heap-allocated memory that must be freed by the caller.
 *
 * @param [in] keepalive The keepalive threshold before which an agent should be set as disconnected.
 * @param [in] sync_status String with the cluster synchronization status to be set.
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Pointer to the array, on success. NULL if no agents were set as disconnected or an error ocurred.
 */
int* wdb_disconnect_agents(int keepalive, const char *sync_status, int *sock);

/**
 * @brief Update agent multi group.
 *
 * @param[in] id The agent id.
 * @param[in] group The group name.
 * @param[in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 * @return Returns OS_SUCCESS on success or OS_INVALID on failure.
 */
int wdb_update_agent_multi_group(int id, char *group, int *sock);

/**
 * @brief Fill belongs table on start.
 * @param [in] sock The Wazuh DB socket connection. If NULL, a new connection will be created and closed locally.
 *
 * @return Returns OS_SUCCESS.
 */
int wdb_agent_belongs_first_time(int *sock);

/**
 * @brief Get the agent first registration date.
 *
 * @param[in] agent_id The agent ID.
 * @return Returns the agent first registration date.
 */
time_t get_agent_date_added(int agent_id);


#endif