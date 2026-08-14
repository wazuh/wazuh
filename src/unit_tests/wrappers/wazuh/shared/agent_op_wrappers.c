/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>

#include "agent_op_wrappers.h"

#include "shared.h"
// #include "../../analysisd/logmsg.h"

int __wrap_auth_connect() {
    return mock();
}

char* __wrap_get_agent_id_from_name(__attribute__((unused)) char *agent_name) {
    return mock_type(char*);
}

char* __wrap_getPrimaryIP(void) {
    return mock_type(char*);
}

cJSON* __wrap_w_create_sendsync_payload(const char *daemon_name, cJSON *message) {
    check_expected(daemon_name);

    if (mock()) {
        cJSON_Delete(message);
    }

    return mock_type(cJSON*);
}

int __wrap_w_send_clustered_message(const char* command, const char* payload, char* response) {
    check_expected(command);
    check_expected(payload);

    strcpy(response, mock_type(char*));

    return mock();
}

bool __wrap_w_query_agentd(const char *module, const char *query, char *output, size_t output_size) {
    check_expected(module);
    check_expected(query);

    const char* mock_output = mock_ptr_type(char*);
    if (mock_output && output && output_size > 0) {
        strncpy(output, mock_output, output_size - 1);
        output[output_size - 1] = '\0';
    }

    return mock_type(bool);
}
