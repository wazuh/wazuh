/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SCHEMA_VALIDATOR_WRAPPERS_H
#define SCHEMA_VALIDATOR_WRAPPERS_H

#include <stdbool.h>

/**
 * @brief Wrapper for schema_validator_is_initialized
 */
bool __wrap_schema_validator_is_initialized(void);

/**
 * @brief Wrapper for schema_validator_initialize
 */
bool __wrap_schema_validator_initialize(void);

/**
 * @brief Wrapper for schema_validator_validate
 */
bool __wrap_schema_validator_validate(const char* indexPattern,
                                      const char* message,
                                      char** errorMessage);

#endif
