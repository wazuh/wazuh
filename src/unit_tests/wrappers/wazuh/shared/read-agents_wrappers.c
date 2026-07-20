/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "read-agents_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <stdint.h>
#include <cmocka.h>

int __wrap_connect_to_remoted() {
    return mock();
}

int __wrap_send_msg_to_agent(int msocket, const char *msg, const char *agt_id, const char *exec) {
    check_expected(msocket);
    check_expected(msg);
    check_expected(agt_id);
    check_expected_ptr(exec);

    return mock();
}
