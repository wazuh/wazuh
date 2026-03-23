/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 30, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef REM_CONFIG_WRAPPERS_H
#define REM_CONFIG_WRAPPERS_H

#include <cJSON.h>

cJSON *__wrap_getRemoteConfig();

#endif /* REM_CONFIG_WRAPPERS_H */
