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
#include "remoted_op_wrappers.h"

int __wrap_parse_agent_update_msg(char *msg, __attribute__((unused)) agent_info_data *agent_data) {
    check_expected(msg);
    agent_info_data *aux = mock_ptr_type(agent_info_data*);
    memcpy(agent_data, aux, sizeof(agent_info_data));
    return mock();
}

int __wrap_parse_json_keepalive(const char *json_str, __attribute__((unused)) agent_info_data *agent_data,
                                 __attribute__((unused)) char ***groups_out, __attribute__((unused)) size_t *groups_count_out) {
    check_expected(json_str);
    agent_info_data *aux = mock_ptr_type(agent_info_data*);
    memcpy(agent_data, aux, sizeof(agent_info_data));
    return mock();
}
