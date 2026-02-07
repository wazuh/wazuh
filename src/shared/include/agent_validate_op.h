/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef AGENT_VALIDATE_OP_H
#define AGENT_VALIDATE_OP_H

#include <time.h>
#include "sec.h"

/* Forward declaration to avoid circular dependency */
typedef struct _keystore keystore;

#define OS_ADDAGENT_LIMIT_REACHED -2
#define FILE_SIZE                 257
#define STR_SIZE                  66
#define VALID_AGENT_NAME_CHARS    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_.-"

// Validation and agent management functions
int OS_AddNewAgent(
    keystore* keys, const char* id, const char* name, const char* ip, const char* key, unsigned int max_agents);
int OS_IsValidID(const char* id);
char* getNameById(const char* id);
int IDExist(const char* id, int discard_removed);
int OS_IsValidName(const char* u_name);
void OS_ConvertToValidAgentName(char* u_name);
int NameExist(const char* u_name);
char* IPExist(const char* u_ip);
void OS_AddAgentTimestamp(const char* id, const char* name, const char* ip, time_t now);
void OS_RemoveAgentTimestamp(const char* id);
void FormatID(char* id);

#endif // AGENT_VALIDATE_OP_H
