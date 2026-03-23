/*
 * Shared functions for querying wazuh-agentd
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef AGENTD_QUERY_H
#define AGENTD_QUERY_H

#include <stdbool.h>
#include <stddef.h>

/**
 * @brief Query wazuh-agentd via local socket or agcom_dispatch
 *
 * Sends a command to wazuh-agentd and receives the response. On Unix/Linux,
 * this uses a Unix domain socket. On Windows, it uses agcom_dispatch.
 *
 * The response format from agentd is expected to be:
 * - "ok <json_data>" on success
 * - "err <error_message>" on error
 *
 * @param log_tag Module-specific log tag for logging (e.g., WM_SYS_LOGTAG)
 * @param command Command to send to agentd (e.g., "getdoclimits sca")
 * @param output_buffer Buffer to store the JSON response (without "ok " prefix)
 * @param buffer_size Size of output_buffer
 * @return true on success with output_buffer populated, false on failure
 */
bool w_query_agentd(const char* log_tag, const char* command,
                    char* output_buffer, size_t buffer_size);

#endif /* AGENTD_QUERY_H */
