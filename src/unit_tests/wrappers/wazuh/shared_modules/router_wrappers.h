/*
 * Wazuh router wrappers
 * Copyright (C) 2015, Wazuh Inc.
 * Aug 29, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef ROUTER_WRAPPERS_H
#define ROUTER_WRAPPERS_H

#include "../../common.h"
#include <stdbool.h>
#include "router.h"

int __wrap_router_provider_send(ROUTER_PROVIDER_HANDLE handle, const char* message, unsigned int message_size);

ROUTER_PROVIDER_HANDLE __wrap_router_provider_create(const char* name);

// Router subscriber wrappers for agent upgrade module
ROUTER_SUBSCRIBER_HANDLE __wrap_router_subscriber_create(const char* topic_name, const char* subscriber_id, bool is_local);

int __wrap_router_subscriber_subscribe(ROUTER_SUBSCRIBER_HANDLE handle, void (*callback)(const char*));

int __wrap_router_subscriber_unsubscribe(ROUTER_SUBSCRIBER_HANDLE handle);

int __wrap_router_subscriber_destroy(ROUTER_SUBSCRIBER_HANDLE handle);

#endif // ROUTER_WRAPPERS_H
