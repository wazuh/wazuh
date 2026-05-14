/* Copyright (C) 2025, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "../../../syscheckd/include/syscheck.h"
#include "ebpf_wrappers.h"
#include <setjmp.h>
#include <cmocka.h>


int __wrap_ebpf_whodata_healthcheck() {
    // Your function definition goes here
    return mock_type(int);
}

typedef void (*FunctionPtr)();

void __wrap_fimebpf_initialize(const char* config_dir,
                                FunctionPtr get_user,
                                FunctionPtr get_group,
                                FunctionPtr whodata_event,
                                FunctionPtr free_whodata_event,
                                FunctionPtr loggingFunction,
                                FunctionPtr abspath,
                                FunctionPtr is_shutdown,
                                syscheck_config syscheck) {
}
