/* Copyright (C) 2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LIMITS_H
#define LIMITS_H

#include "shared.h"

#define LIMITS_SUCCESS                   0  ///< Return code: Successful
#define LIMITS_NULL_NAME                -1  ///< Return code: Null name argument
#define LIMITS_FILE_NOT_FOUND           -2  ///< Return code: Limits.conf file not found
#define LIMITS_FILE_DOESNT_CHANGE       -3  ///< Return code: Limits.conf file doesn't chage datetime arguments
#define LIMITS_OPEN_FILE_FAIL           -4  ///< Return code: Open file Limits.conf fail
#define LIMITS_READ_FILE_FAIL           -5  ///< Return code: Read file Limits.conf fail
#define LIMITS_JSON_FORMAT_FAIL         -6  ///< Return code: Limits.conf doesn't have a valid json format
#define LIMITS_JSON_LIMIT_NOT_FOUND     -7  ///< Return code: Limits section doesn't found in json
#define LIMITS_JSON_DAEMON_NOT_FOUND    -8  ///< Return code: Daemon name section doesn't found in json


int load_limits_file(const char *daemon_name, cJSON ** daemon_obj);

#endif
