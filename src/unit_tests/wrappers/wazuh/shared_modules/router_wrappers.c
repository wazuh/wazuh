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
#include <stdint.h>
#include "router.h"

int __wrap_router_provider_send(__attribute__((unused)) ROUTER_PROVIDER_HANDLE handle,
                                const char* message,
                                unsigned int message_size) {
    check_expected(message);
    check_expected(message_size);
    return mock();
}

ROUTER_PROVIDER_HANDLE __wrap_router_provider_create(const char* name) {
    check_expected(name);
    return mock_ptr_type(ROUTER_PROVIDER_HANDLE);
}

// Router subscriber wrappers for agent upgrade module
ROUTER_SUBSCRIBER_HANDLE __wrap_router_subscriber_create(const char* topic_name, const char* subscriber_id, bool is_local) {
    check_expected(topic_name);
    check_expected(subscriber_id);
    check_expected(is_local);
    return mock_ptr_type(ROUTER_SUBSCRIBER_HANDLE);
}

int __wrap_router_subscriber_subscribe(__attribute__((unused)) ROUTER_SUBSCRIBER_HANDLE handle,
                                      __attribute__((unused)) void (*callback)(const char*)) {
    check_expected(handle);
    return mock();
}

int __wrap_router_subscriber_unsubscribe(__attribute__((unused)) ROUTER_SUBSCRIBER_HANDLE handle) {
    check_expected(handle);
    return mock();
}

int __wrap_router_subscriber_destroy(__attribute__((unused)) ROUTER_SUBSCRIBER_HANDLE handle) {
    check_expected(handle);
    return mock();
}
