/*
 * Wazuh router wrappers
 * Copyright (C) 2015, Wazuh Inc.
 * Aug 24, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "../../common.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include "router.h"

int __wrap_router_provider_send(__attribute__((unused)) ROUTER_PROVIDER_HANDLE handle,
                                const char* message,
                                unsigned int message_size) {
    check_expected(message);
    check_expected(message_size);
    return mock();
}

int __wrap_router_provider_send_fb(__attribute__((unused)) ROUTER_PROVIDER_HANDLE handle,
                                const char* msg,
                                const char* schema) {
    check_expected(msg);
    check_expected(schema);
    return mock();
}

ROUTER_PROVIDER_HANDLE __wrap_router_provider_create(const char* name) {
    check_expected(name);
    return mock_ptr_type(ROUTER_PROVIDER_HANDLE);
}
