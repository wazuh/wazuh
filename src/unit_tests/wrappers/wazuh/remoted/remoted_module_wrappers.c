/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "remoted_module_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

void __wrap_remoted_module_start(__attribute__((unused)) const logging_callback_t logCb,
                                  __attribute__((unused)) const remoted_module_config_t* config) {
    // Mock implementation - does nothing in tests
}

void __wrap_remoted_module_stop(void) {
    // Mock implementation - does nothing in tests
}
