/* Copyright (C) 2015-2021, Wazuh Inc.
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
#include "../../analysisd/logmsg.h"

int __wrap_auth_connect() {
    return mock();
}

int __wrap_w_request_agent_add_clustered(char *err_response,
                                        const char *name,
                                        const char *ip,
                                        const char *groups,
                                        const char *key_hash,
                                        char **id,
                                        char **key,
                                        const int force,
                                        const char *agent_id) {
    check_expected(err_response);
    check_expected(name);
    check_expected(ip);
    check_expected(groups);
    check_expected(key_hash);
    check_expected(id);
    check_expected(key);
    check_expected(force);
    check_expected(agent_id);
    return mock();
}

char* __wrap_get_agent_id_from_name(__attribute__((unused)) char *agent_name) {
    return mock_type(char*);
}

int __wrap_control_check_connection() {
    return mock();
}

int __wrap_get_agent_group(const char *id, char *group, __attribute__((unused)) size_t size) {
    check_expected(id);
    strncpy(group, mock_type(char *), OS_SIZE_65536);
    return mock();
}

int __wrap_set_agent_group(const char * id, const char * group) {
    check_expected(id);
    check_expected(group);
    return mock();
}
