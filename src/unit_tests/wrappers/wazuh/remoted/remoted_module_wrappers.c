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
#include <string.h>
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

int __wrap_remoted_module_tls_ca_matches_leaf(void) {
    return mock_type(int);
}

int __wrap_remoted_module_tls_leaf_signer_pem(char* buffer, size_t capacity) {
    const char* pem = mock_ptr_type(const char*);
    int written = mock_type(int);

    if (pem != NULL && written > 0) {
        size_t length = strlen(pem);

        if (length > capacity) {
            length = capacity;
        }

        memcpy(buffer, pem, length);
    }

    return written;
}
