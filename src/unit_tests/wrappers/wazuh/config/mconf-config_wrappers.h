/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef MCONF_CONFIG_WRAPPERS
#define MCONF_CONFIG_WRAPPERS

#include "../../../../external/cJSON/cJSON.h"

/* w_mconf_load(): expect_string(cfgfile) + will_return(status). */
int __wrap_w_mconf_load(const char *cfgfile);

/* w_mconf_section(): expect_string(section) + will_return(cJSON *) — the caller frees the object,
 * so queue a fresh cJSON_Parse() result (or NULL) for every expected call. */
cJSON *__wrap_w_mconf_section(const char *section);

#endif // MCONF_CONFIG_WRAPPERS
