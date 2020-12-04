/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */
#ifndef __MACH__
#include "libaudit_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>


int __wrap_audit_add_rule_data() {
    return mock();
}

int __wrap_audit_add_watch_dir(int type,
                               __attribute__((unused)) struct audit_rule_data **rulep,
                               const char *path) {
    check_expected(type);
    check_expected(path);

    return mock();
}

int __wrap_audit_close() {
    return mock();
}

int __wrap_audit_delete_rule_data() {
    return mock();
}

char *__wrap_audit_errno_to_name() {
    return mock_type(char *);
}

int __wrap_audit_get_reply(int fd,
                           struct audit_reply *rep,
                           reply_t block,
                           __attribute__((unused)) int peek) {
    check_expected(fd);
    check_expected(block);

    struct audit_reply *reply = mock_type(struct audit_reply *);
    if (reply) {
        *rep = *reply;
    }

    return mock();
}

int __wrap_audit_open() {
    return mock();
}

int __wrap_audit_rule_fieldpair_data(__attribute__((unused)) struct audit_rule_data **rulep,
                                     const char *pair,
                                     int flags) {
    check_expected(pair);
    check_expected(flags);

    return mock();
}

int __wrap_audit_send(int fd,
                      int type,
                      const void *data,
                      __attribute__((unused)) unsigned int size) {
    check_expected(fd);
    check_expected(type);
    check_expected(data);

    return mock();
}

int __wrap_audit_update_watch_perms(__attribute__((unused)) struct audit_rule_data *rule,
                                    int perms) {
    check_expected(perms);

    return mock();
}

int __wrap_audit_request_status(__attribute__((unused)) int fd) {
    return mock();
}

#endif
