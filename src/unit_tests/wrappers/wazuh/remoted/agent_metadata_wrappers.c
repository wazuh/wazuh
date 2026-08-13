/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <stdint.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdint.h>
#include "agent_metadata_wrappers.h"

agent_meta_t* __wrap_agent_meta_from_agent_info(const char* id_str,
                                                const char* agent_name,
                                                const struct agent_info_data* ai) {
    check_expected(id_str);
    check_expected(agent_name);
    check_expected(ai);

    return mock_ptr_type(agent_meta_t*);
}

int __wrap_agent_meta_upsert_locked(const char* agent_id_str, agent_meta_t* fresh) {
    check_expected(agent_id_str);
    check_expected(fresh);

    return mock_type(int);
}

int __wrap_agent_meta_snapshot_str(const char* agent_id_str, agent_meta_t* out) {
    check_expected(agent_id_str);
    check_expected(out);
    return mock_type(int);
}
