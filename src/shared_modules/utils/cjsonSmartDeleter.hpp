/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _CJSON_SMART_DELETER_HPP
#define _CJSON_SMART_DELETER_HPP

#include "cJSON.h"
#include "customDeleter.hpp"

struct CJsonSmartFree final : CustomDeleter<decltype(&cJSON_free), cJSON_free>
{
};
struct CJsonSmartDeleter final : CustomDeleter<decltype(&cJSON_Delete), cJSON_Delete>
{
};

#endif // _CJSON_SMART_DELETER_HPP
