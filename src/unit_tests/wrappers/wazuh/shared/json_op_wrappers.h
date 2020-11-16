/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef JSON_OP_WRAPPERS_H
#define JSON_OP_WRAPPERS_H

#include "headers/shared.h"

cJSON * __wrap_json_fread(const char * path, char retry);

#endif
