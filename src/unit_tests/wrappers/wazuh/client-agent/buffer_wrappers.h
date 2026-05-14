/*
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef BUFFER_WRAPPERS_H
#define BUFFER_WRAPPERS_H

#include <pthread.h>
#include "shared.h"
#include "../../../client-agent/agentd.h"

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif

int __wrap_w_agentd_get_buffer_lenght();

#endif
