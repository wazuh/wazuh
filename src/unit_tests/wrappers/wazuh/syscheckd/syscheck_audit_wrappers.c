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

void __wrap_audit_read_events(int *audit_sock, int mode) {
    check_expected(mode);
    *audit_sock = mock_type(int);
}

int __wrap_init_auditd_socket(void) {
    return mock_type(int);
}
