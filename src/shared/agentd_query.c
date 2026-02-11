/*
 * Shared functions for querying wazuh-agentd
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "shared.h"
#include "agentd_query.h"
#include "os_net/os_net.h"

#ifdef WIN32
extern size_t agcom_dispatch(char * command, char ** output);
#endif

bool w_query_agentd(const char* log_tag, const char* command,
                    char* output_buffer, size_t buffer_size)
{
    if (!log_tag || !command || !output_buffer || buffer_size == 0)
    {
        return false;
    }

    // Temporary buffer for receiving full response (including "ok " or "err " prefix)
    char response_buffer[OS_MAXSTR];
    ssize_t response_length = 0;

#ifndef WIN32
    // Unix/Linux: Use socket communication to get response into buffer
    const char* AGENT_SOCKET = "queue/sockets/agent";
    const size_t MAX_RECV_SIZE = sizeof(response_buffer) - 1;

    // Connect to agent socket
    int sock = OS_ConnectUnixDomain(AGENT_SOCKET, SOCK_STREAM, MAX_RECV_SIZE);
    if (sock < 0)
    {
        mtdebug1(log_tag, "Could not connect to agent socket: %s", strerror(errno));
        return false;
    }

    // Send request
    if (OS_SendSecureTCP(sock, strlen(command), command) != 0)
    {
        mterror(log_tag, "Failed to send request to agent socket: %s", strerror(errno));
        close(sock);
        return false;
    }

    // Receive response (leave room for null terminator)
    memset(response_buffer, 0, sizeof(response_buffer));
    response_length = OS_RecvSecureTCP(sock, response_buffer, MAX_RECV_SIZE);
    close(sock);

    if (response_length <= 0)
    {
        if (response_length == 0)
        {
            mtdebug1(log_tag, "Empty response from agent socket");
        }
        else if (response_length == -2)  // OS_SOCKTERR
        {
            mterror(log_tag, "Maximum buffer length reached reading from agent socket");
        }
        else
        {
            mterror(log_tag, "Failed to receive response from agent socket: %s", strerror(errno));
        }
        return false;
    }

    // Ensure null termination (response_length is guaranteed <= MAX_RECV_SIZE)
    response_buffer[response_length] = '\0';
#else
    // Windows: Use agcom_dispatch and copy response into buffer
    // Note: agcom_dispatch modifies the command string, so we need a mutable copy
    char command_copy[OS_MAXSTR];
    strncpy(command_copy, command, sizeof(command_copy) - 1);
    command_copy[sizeof(command_copy) - 1] = '\0';

    char* output = NULL;
    size_t result = agcom_dispatch(command_copy, &output);

    if (result == 0 || !output)
    {
        mtdebug1(log_tag, "Failed to query agentd via agcom_dispatch");
        return false;
    }

    // Copy response to our temporary buffer (safely)
    size_t output_len = strlen(output);
    size_t max_copy = sizeof(response_buffer) - 1;
    if (output_len > max_copy)
    {
        mtwarn(log_tag, "Response too large (%zu bytes), truncating to %zu bytes",
               output_len, max_copy);
        output_len = max_copy;
    }

    memcpy(response_buffer, output, output_len);
    response_buffer[output_len] = '\0';
    response_length = output_len;
    os_free(output);
#endif

    // Common response parsing (works for both platforms)
    mtdebug2(log_tag, "Response from agentd: %s", response_buffer);

    // Check if response starts with "ok "
    if (response_length >= 3 && strncmp(response_buffer, "ok ", 3) == 0)
    {
        // Copy JSON part (after "ok ") to output buffer
        const char* json_start = response_buffer + 3;
        size_t json_len = strlen(json_start);

        if (json_len >= buffer_size)
        {
            mterror(log_tag, "Output buffer too small (%zu bytes needed, %zu available)",
                    json_len + 1, buffer_size);
            return false;
        }

        strncpy(output_buffer, json_start, buffer_size - 1);
        output_buffer[buffer_size - 1] = '\0';
        return true;
    }
    else if (response_length >= 4 && strncmp(response_buffer, "err ", 4) == 0)
    {
        // Error response from agentd
        mtdebug1(log_tag, "Agentd returned error: %s", response_buffer + 4);
        return false;
    }
    else
    {
        mterror(log_tag, "Unexpected response format from agentd: %s", response_buffer);
        return false;
    }
}
