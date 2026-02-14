/*
 * JSON support library
 * Copyright (C) 2015, Wazuh Inc.
 * May 11, 2018.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef JSON_OP_H
#define JSON_OP_H

#define JSON_MAX_FSIZE 2147483648

#include <cJSON.h>

/**
 * @brief It temporarily saves in memory the content of the file located in path.
 * It also allows requesting and verifying that the JSON has a null termination
 * and recovers the pointer to the last parsed byte.
 *
 * @param path  location of the file to be read.
 * @param retry if set to 1, allows the operation to be retried if json parsing fails. It also removes C/C++ type comments.
 * If it is set to 0, it does not perform the retry.
 * @return cJSON*
 */
cJSON * json_fread(const char * path, char retry);

/**
 * @brief Represent a cJSON entity in plain text for storage in the file located at path.
 *
 * @param path location of the file to be write.
 * @param item json entity to be represented in text.
 * @return int stores the result of the write operation. If it returns -1 it indicates that the operation was not carried out correctly.
 * If it returns 0, it indicates that the operation was successful.
 */
int json_fwrite(const char * path, const cJSON * item);

/**
 * @brief Clear C/C++ style comments from a JSON string.
 *
 * @param json json to which comment stripping is applied.
 */
void json_strip(char * json);

// Check if a JSON object is tagged
#define json_tagged_obj(x) (x && x->string)

/**
 * Parses agents array and returns an array of agent ids
 * @param agents array of agents
 * @return pointer to array of agent ids
 * */
int* json_parse_agents(const cJSON* agents);

#endif
