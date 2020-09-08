/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "create_db_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_fim_checker(char *path,
                        __attribute__((unused)) fim_element *item,
                        whodata_evt *w_evt,
                        int report) {
    check_expected(path);
    check_expected(w_evt);
    check_expected(report);
}

int __wrap_fim_configuration_directory(const char *path,
                                       const char *entry) {
    check_expected(path);
    check_expected(entry);
    return mock();
}

cJSON *__wrap_fim_entry_json(const char * path,
                             __attribute__((unused)) fim_entry_data * data) {
    check_expected(path);
    return mock_type(cJSON*);
}

cJSON *__wrap_fim_json_event() {
    return mock_type(cJSON *);
}

void __wrap_fim_realtime_event(char *file) {
    check_expected(file);
}

int __wrap_fim_registry_event(__attribute__((unused)) char *key,
                              __attribute__((unused)) fim_entry_data *data,
                              __attribute__((unused)) int pos) {
    return mock();
}

int __wrap_fim_whodata_event(whodata_evt * w_evt)
{
    if (w_evt->process_id) check_expected(w_evt->process_id);
    if (w_evt->user_id) check_expected(w_evt->user_id);
    if (w_evt->process_name) check_expected(w_evt->process_name);
    if (w_evt->path) check_expected(w_evt->path);
#ifndef WIN32
    if (w_evt->group_id) check_expected(w_evt->group_id);
    if (w_evt->audit_uid) check_expected(w_evt->audit_uid);
    if (w_evt->effective_uid) check_expected(w_evt->effective_uid);
    if (w_evt->inode) check_expected(w_evt->inode);
    if (w_evt->ppid) check_expected(w_evt->ppid);
#endif
    return 1;
}
