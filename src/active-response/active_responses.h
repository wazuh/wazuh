/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"

#ifndef WIN32
#define LOG_FILE "logs/active-responses.log"
#else
#define LOG_FILE "active-response\\active-responses.log"
#endif

#define COMMANDSIZE_4096 4096

#define VERSION 1
#define AR_MODULE_NAME "active-response"
#define CHECK_KEYS_ENTRY "check_keys"

/**
 * Enumeration of the available commands
 * */
typedef enum _ar_command_list {
    ADD_COMMAND = 0,
    DELETE_COMMAND,
    CONTINUE_COMMAND,
    ABORT_COMMAND
} ar_command_list;

/**
 * Write the incomming message in active-responses log file.
 * @param ar_name Name of active response
 * @param msg Incomming message to write
 * */
void write_debug_file(const char *ar_name, const char *msg);

/**
 * @brief Set wazuh home directory and check message from stdin
 * @param argv Arguments of the script
 * @param message JSON message from stdin
 * @return Command from message
 */
int setup_and_check_message(char **argv, cJSON **message);

/**
 * @brief Send message with keys and check message from stdin
 * @param argv Arguments of the script
 * @param keys Keys to be sent
 * @return Command from message
 */
int send_keys_and_check_message(char **argv, char **keys);

/**
 * Get the json structure from input
 * Caller must call cJSON_Delete() to release the object
 * @param input Input to validate
 * @return JSON input or NULL on Invalid
 * */
cJSON* get_json_from_input(const char *input);

/**
 * Get command from input
 * @param input Input
 * @return char * with the command or NULL on fail
 * */
const char* get_command_from_json(const cJSON *input);

/**
 * Get alert from input
 * @param input Input
 * @return JSON alert or NULL on Invalid.
 * */
const cJSON* get_alert_from_json(const cJSON *input);

/**
 * Get srcip from input
 * @param input Input
 * @return char * with the srcip or NULL on fail
 * */
const char* get_srcip_from_json(const cJSON *input);

/**
 * Get username from input
 * @param input Input
 * @return char * with the username or NULL on fail
 * */
const char* get_username_from_json(const cJSON *input);

/**
 * Get extra_args from input
 * @param input Input
 * @return char * with the extra_args or NULL on fail
 * */
char* get_extra_args_from_json(const cJSON *input);

/**
 * Get keys from input
 * @param input Input
 * @return char * with the keys or NULL on fail
 * */
char* get_keys_from_json(const cJSON *input);

/**
 * @brief This function splits a string using a delimiter
 * @param output_buf buffer output
 * @param delimiter  delimiter used to split the string
 * @param strBefore  buffer to store split string before delimiter
 * @param strAfter   buffer to store split string after delimiter
*/
void splitStrFromCharDelimiter(const char * output_buf, const char delimiter, char * strBefore, char * strAfter);

/**
 * @brief It looks for a string that matches pattern 1, if it finds it, it looks again for pattern 2, there should be spaces in the middle between the patterns.
 * @param output_buf buffer where search
 * @param str_pattern_1 pattern to match
 * @param str_pattern_2 pattern to match
 * @return 1 or 0
 * @example output_buf -> "... Status:    Disabled ..."
 *          isEnabledFromPattern(output_buf, "Status: ", "Enabled")
 *            if it matches pattern 1 look for pattern 2 and if found, it returns 1
 *          isEnabledFromPattern(output_buf, "Status: ", NULL)
 *            find only by "Status"
*/
int isEnabledFromPattern(const char * output_buf, const char * str_pattern_1, const char * str_pattern_2);

#ifndef WIN32

/**
 * Write process pid to lock simultaneous executions of the script
 * @param lock_path Path of the folder to lock
 * @param lock_pid_path Path of the file to lock
 * @param log_path Messages log file
 * @param proc_name Name of the proces to lock/unlock
 * @return OS_SUCCESS or OS_INVALID
 * */
int lock(const char *lock_path, const char *lock_pid_path, const char *log_path, const char *proc_name);

/**
 * Remove lock
 * @param lock_path Path of the folder to lock
 * @param log_path Messages log file
 * */
void unlock(const char *lock_path, const char *log_path);

/**
 * Check ip version from a string
 * @param ip Ip to check version
 * @retval 4 If ip is ipv4
 * @retval 6 If ip is ipv6
 * @retval OS_INVALID on Invalid IP or error
 * */
int get_ip_version(const char *ip);

#endif
