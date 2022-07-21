/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2015 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef TO_JSON_H
#define TO_JSON_H

#include "../eventinfo.h"

#define add_json_field(obj, name, string, filter) if (string && strcmp(string, filter)) { if (!obj) obj = cJSON_CreateObject(); cJSON_AddStringToObject(obj, name, string); }
char *Eventinfo_to_jsonstr(const Eventinfo *lf, bool force_full_log, OSList * list_msg);
#endif /* TO_JSON_H */
