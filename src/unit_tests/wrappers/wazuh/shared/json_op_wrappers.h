/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef JSON_OP_WRAPPERS_H
#define JSON_OP_WRAPPERS_H

#include "../../../../headers/shared.h"

cJSON * __wrap_json_fread(const char * path, char retry);
int __wrap_json_fwrite(const char * path, const cJSON * item);

int* __wrap_json_parse_agents(const cJSON* agents);

int* __wrap_json_parse_agents(const cJSON* agents);

#endif
