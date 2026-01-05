/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "schema_validator_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>

bool __wrap_schema_validator_is_initialized(void) {
    return mock_type(bool);
}

bool __wrap_schema_validator_initialize(void) {
    return mock_type(bool);
}

bool __wrap_schema_validator_validate(const char* indexPattern,
                                      const char* message,
                                      char** errorMessage) {
    check_expected_ptr(indexPattern);
    check_expected_ptr(message);

    if (errorMessage != NULL) {
        *errorMessage = mock_ptr_type(char*);
    }

    return mock_type(bool);
}
