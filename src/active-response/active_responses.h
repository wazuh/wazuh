/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

#ifndef WIN32
#define LOG_FILE "/logs/active-responses.log"
#else
#define LOG_FILE "active-response\\active-responses.log"
#endif
#define ECHO "/bin/echo"
#define PASSWD "/usr/bin/passwd"
#define CHUSER "/usr/bin/chuser"
#define BUFFERSIZE 4096
#define LOGSIZE 8192
#define COMMANDSIZE 2048

/**
 * Write the incomming message in active-responses log file.
 * @param ar_name Name of active response.
 * @param msg Incomming message to write.
 * */
void write_debug_file (const char *ar_name, const char *msg);

/**
 * Get the json structure from input
 * @param input Input to validate
 * @return JSON input or NULL on Invalid.
 * */
cJSON* get_json_from_input (const char *input);

/**
 * Get command from input
 * @param input Input
 * @return char * with the command or NULL on fail
 * */
char* get_command (cJSON *input);

/**
 * Get username from input
 * @param input Input
 * @return char * with the username or NULL on fail
 * */
char* get_username_from_json (cJSON *input);

/**
 * Get srcip from input
 * @param input Input
 * @return char * with the srcip or NULL on fail
 * */
char* get_srcip_from_json (cJSON *input);

/**
 * Check for valid IP and version
 * @param ip IP
 * @return IP version or -1 on fail
 * */
int get_ip_version (char *ip);
