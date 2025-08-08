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
#include "manager_wrappers.h"

cJSON *__wrap_assign_group_to_agent(const char *agent_id, const char *md5) {
    check_expected(agent_id);
    check_expected(md5);

    return mock_type(cJSON *);
}

void __wrap_save_controlmsg(const keyentry * key, char *r_msg, __attribute__((unused)) size_t msg_length, int *wdb_sock) {
    check_expected(key);
    check_expected(r_msg);
    check_expected(wdb_sock);

    return;
}

int __wrap_validate_control_msg(const keyentry * key, char *r_msg, size_t msg_length,  __attribute__((unused)) char **cleaned_msg,  __attribute__((unused)) int *is_startup,  __attribute__((unused)) int *is_shutdown) {
    check_expected(key);
    check_expected(r_msg);
    check_expected(msg_length);

    return mock_type(int);
}
