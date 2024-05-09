/*
 * Utils Agent Messages Adapter
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 29, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _AGENT_MESSAGES_HELPER_HPP
#define _AGENT_MESSAGES_HELPER_HPP

#include "hash_op.h"

/**
 * @brief Duplicator method for hash table
 *
 * @param data
 * @return void*
 */
void *agent_data_hash_duplicator(void* data);

/**
 * @brief Takes a syscollector delta message and adapts it to a format compatible with the defined flatbuffer schema.
 *
 * @param data Agent message.
 * @param name Name of the agent.
 * @param id Id of the agent.
 * @param ip Ip of the agent.
 * @return char* Returns a string representation of the JSON formatted message. Must be freed by the caller.
 */
char* adapt_delta_message(const char* data, const char* name, const char* id, const char* ip, const OSHash *agent_data_hash);

/**
 * @brief Takes a syscollector synchronization message and adapts it to a format compatible with the defined flatbuffer schema.
 *
 * @param data Agent message.
 * @param name Name of the agent.
 * @param id Id of the agent.
 * @param ip Ip of the agent.
 * @return char* Returns a string representation of the JSON formatted message. Must be freed by the caller.
 */
char* adapt_sync_message(const char* data, const char* name, const char* id, const char* ip, const OSHash *agent_data_hash);

#endif // _AGENT_MESSAGES_HELPER_HPP
