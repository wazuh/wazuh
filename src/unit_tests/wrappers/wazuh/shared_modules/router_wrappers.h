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

int __wrap_router_provider_send_fb(ROUTER_PROVIDER_HANDLE handle, const char* message, const char* schema);

ROUTER_PROVIDER_HANDLE __wrap_router_provider_create(const char* name);

#endif // ROUTER_WRAPPERS_H
