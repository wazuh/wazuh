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

#include "agent_op_wrappers.h"

#include "../../headers/shared.h"
// #include "../../analysisd/logmsg.h"

int __wrap_auth_connect() {
    return mock();
}

int __wrap_w_request_agent_add_clustered(__attribute__((unused)) char *err_response,
                                         __attribute__((unused)) const char *name,
                                         __attribute__((unused)) const char *ip,
                                         __attribute__((unused)) const char *groups,
                                         __attribute__((unused)) const char *key_hash,
                                         __attribute__((unused)) char **id,
                                         __attribute__((unused)) char **key,
                                         __attribute__((unused)) const int force,
                                         __attribute__((unused)) const char *agent_id) {
    return mock();
}

char* __wrap_get_agent_id_from_name(__attribute__((unused)) char *agent_name) {
    return mock_type(char*);
}

int __wrap_control_check_connection() {
    return mock();
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

int __wrap_getsockname(int fd, struct sockaddr* addr, __attribute__((unused)) socklen_t* len) {
    int ret = -1;
    if(fd) {
        ret = mock();
        addr->sa_family = mock();
    }
    return ret;
}
