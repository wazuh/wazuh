/*
 * Copyright (C) 2015, Wazuh Inc.
 * April 15, 2019.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef WDBOP_H
#define WDBOP_H

#include "os_net.h"
#include "shared.h"

#define WDBQUERY_SIZE  OS_BUFFER_SIZE
#define WDBOUTPUT_SIZE OS_MAXSTR

#define FIELD_SEPARATOR_DBSYNC        "|"
#define FIELD_SEPARATOR_DBSYNC_ESCAPE "\uffff"

/// Enumeration of agents disconected status reasons.
typedef enum agent_status_code_t
{
    INVALID_VERSION = 1, ///< Invalid agent version
    ERR_VERSION_RECV,    ///< Error retrieving version
    HC_SHUTDOWN_RECV,    ///< Shutdown message received
    NO_KEEPALIVE,        ///< Disconnected because no keepalive received
    RESET_BY_MANAGER,    ///< Connection reset by manager
} agent_status_code_t;

/// OS information data structure
typedef struct os_data
{
    char* os_name;
    char* os_version;
    char* os_major;
    char* os_minor;
    char* os_codename;
    char* os_platform;
    char* os_build;
    char* os_uname;
    char* os_arch;
    char* os_type;
    char* hostname;
} os_data;

/// Agent information data structure
typedef struct agent_info_data
{
    int id;
    os_data* osd;
    char* version;
    char* config_sum;
    char* merged_sum;
    char* manager_host;
    char* node_name;
    char* agent_ip;
    char* labels;
    char* connection_status;
    char* sync_status;
    char* group_config_status;
    agent_status_code_t status_code;
} agent_info_data;

/// Wazuh DB backup settings
typedef struct wdb_backup_settings_node
{
    bool enabled;
    time_t interval;
    int max_files;
} wdb_backup_settings_node;

/// Wazuh DB configuration
typedef struct wdb_config
{
    int worker_pool_size;
    int commit_time_min;
    int commit_time_max;
    int open_db_limit;
    int fragmentation_threshold;
    int fragmentation_delta;
    int free_pages_percentage;
    int max_fragmentation;
    int check_fragmentation_interval;
    wdb_backup_settings_node** wdb_backup_settings;
    bool is_worker_node; ///< Indicates if the node is a cluster worker node
} wdb_config;

/// Wazuh DB configuration variable
extern wdb_config wconfig;

/// Enumeration of communication with Wazuh DB status.
typedef enum wdbc_result
{
    WDBC_OK,     ///< Command processed successfully
    WDBC_DUE,    ///< Command processed successfully with pending data
    WDBC_ERROR,  ///< An error occurred
    WDBC_IGNORE, ///< Command ignored
    WDBC_UNKNOWN ///< Unknown status
} wdbc_result;

extern const char* WDBC_RESULT[];

int wdbc_connect();
int wdbc_connect_with_attempts(int max_attempts);
int wdbc_query(const int sock, const char* query, char* response, const int len);
int wdbc_query_ex(int* sock, const char* query, char* response, const int len);
int wdbc_parse_result(char* result, char** payload);
cJSON* wdbc_query_parse_json(int* sock, const char* query, char* response, const int len);
wdbc_result wdbc_query_parse(int* sock, const char* query, char* response, const int len, char** payload);

/**
 * @brief Closes a socket connection if exists
 *
 * @param[in] sock A Wazuh DB socket connection.
 * @return real close output if sock is connected, 0 otherwise
 */
int wdbc_close(int* sock);

/**
 * @brief Frees agent_info_data struct
 *
 * @param[in] agent_data A agent_info_data struct.
 */
void wdb_free_agent_info_data(agent_info_data* agent_data);

#endif
