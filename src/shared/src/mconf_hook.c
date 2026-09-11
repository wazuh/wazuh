/* Copyright (C) 2015, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CLIENT

#include <stddef.h>
#include "mconf_hook.h"

static w_mconf_section_fn s_provider = NULL;

void w_mconf_hook_set(w_mconf_section_fn fn) {
    s_provider = fn;
}

struct cJSON *w_mconf_hook_section(const char *section) {
    if (s_provider == NULL || section == NULL) {
        return NULL;
    }
    return s_provider(section);
}

#endif /* CLIENT */
