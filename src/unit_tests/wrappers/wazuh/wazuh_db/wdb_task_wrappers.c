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
#include "wdb_task_wrappers.h"

int __wrap_wdb_task_create(__attribute__((unused)) wdb_t* wdb,
                           const char *task_id,
                           const char *agent_id,
                           const char *task_type,
                           const char *payload) {
    check_expected(task_id);
    check_expected(agent_id);
    check_expected(task_type);
    check_expected(payload);

    return mock();
}

int __wrap_wdb_task_get_pending(__attribute__((unused)) wdb_t* wdb,
                                const char *agent_id,
                                int max_tasks,
                                cJSON **tasks_json) {
    check_expected(agent_id);
    check_expected(max_tasks);

    *tasks_json = mock_ptr_type(cJSON*);

    return mock();
}

int __wrap_wdb_task_mark_delivered(__attribute__((unused)) wdb_t* wdb,
                                   const char *task_id,
                                   time_t delivery_time) {
    check_expected(task_id);
    check_expected(delivery_time);

    return mock();
}

int __wrap_wdb_task_cleanup_expired(__attribute__((unused)) wdb_t* wdb,
                                    int ttl) {
    check_expected(ttl);

    return mock();
}

int __wrap_wdb_task_delete_old(__attribute__((unused)) wdb_t* wdb,
                               time_t timestamp) {
    check_expected(timestamp);

    return mock();
}

wdb_t* __wrap_wdb_open_tasks() {
    return mock_ptr_type(wdb_t*);
}
