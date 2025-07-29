/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef VALIDATE_AGENT_H
#define VALIDATE_AGENT_H

#include "shared.h"
#include "sec.h"
#include <cJSON.h>

/** Prototypes **/

/**
 * @brief Converts invalid hostnames to valid by eliminating
 * invalid characters
 *
 * @param u_name name to be converted
 * */
void OS_ConvertToValidAgentName(char *u_name);

/* Validation functions */
int OS_IsValidName(const char *u_name);
int OS_IsValidID(const char *id);
int OS_AddNewAgent(keystore *keys, const char *id, const char *name, const char *ip, const char *key);
void OS_RemoveAgentTimestamp(const char *id);

/* Print available agents */
int print_agents(int print_status, int active_only, int inactive_only, int csv_output, cJSON *json_output);

/* Shared variables */
extern char shost[];

/* Internal defines */
#define FILE_SIZE       257
#define STR_SIZE        66
#define VALID_AGENT_NAME_CHARS "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.-"

/* Print agents */
#define PRINT_AVAILABLE     "\nAvailable agents: \n"
#define PRINT_AGENT         "   ID: %s, Name: %s, IP: %s\n"
#define PRINT_AGENT_STATUS  "   ID: %s, Name: %s, IP: %s, %s\n"

#endif
