/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef __TO_JSON_H__
#define __TO_JSON_H__

#include "eventinfo.h"
#define add_json_field(obj, name, string, filter) if (string && strcmp(string, filter)) { if (!obj) obj = cJSON_CreateObject(); cJSON_AddStringToObject(obj, name, string); }
char *Eventinfo_to_jsonstr(const Eventinfo *lf);
#endif /* __TO_JSON_H__ */
