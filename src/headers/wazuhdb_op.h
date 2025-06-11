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

#include "shared.h"
#include "../os_net/os_net.h"

#define WDBQUERY_SIZE OS_BUFFER_SIZE
#define WDBOUTPUT_SIZE OS_MAXSTR

#define FIELD_SEPARATOR_DBSYNC "|"
#define FIELD_SEPARATOR_DBSYNC_ESCAPE "\uffff"


/// Enumeration of communication with Wazuh DB components.
typedef enum
{
    WB_COMP_SYSCOLLECTOR_PROCESSES,
    WB_COMP_SYSCOLLECTOR_PACKAGES,
    WB_COMP_SYSCOLLECTOR_HOTFIXES,
    WB_COMP_SYSCOLLECTOR_PORTS,
    WB_COMP_SYSCOLLECTOR_NETWORK_PROTOCOL,
    WB_COMP_SYSCOLLECTOR_NETWORK_ADDRESS,
    WB_COMP_SYSCOLLECTOR_NETWORK_IFACE,
    WB_COMP_SYSCOLLECTOR_HWINFO,
    WB_COMP_SYSCOLLECTOR_OSINFO,
    WB_COMP_SYSCOLLECTOR_USERS,
    WB_COMP_SYSCOLLECTOR_GROUPS,
    WB_COMP_SYSCHECK,
    WB_COMP_FIM_FILE,
    WB_COMP_FIM_REGISTRY,
    WB_COMP_FIM_REGISTRY_KEY,
    WB_COMP_FIM_REGISTRY_VALUE,
    WB_COMP_INVALID  // Sentinel value for invalid components
} component_type;

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

extern const char* WDBC_VALID_COMPONENTS[];

int wdbc_connect();
int wdbc_connect_with_attempts(int max_attempts);
int wdbc_query(const int sock, const char *query, char *response, const int len);
int wdbc_query_ex(int *sock, const char *query, char *response, const int len);
int wdbc_parse_result(char *result, char **payload);
component_type wdbc_validate_component(const char* component);
cJSON * wdbc_query_parse_json(int *sock, const char *query, char *response, const int len);
wdbc_result wdbc_query_parse(int *sock, const char *query, char *response, const int len, char** payload);

/**
 * @brief Closes a socket connection if exists
 *
 * @param[in] sock A Wazuh DB socket connection.
 * @return real close output if sock is connected, 0 otherwise
 */
int wdbc_close(int* sock);

#endif
