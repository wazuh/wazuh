/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef EXPRESSION_WRAPPERS_H
#define EXPRESSION_WRAPPERS_H

#include <stdbool.h>
#include "../headers/shared.h"
#include "../headers/expression.h"

bool __wrap_w_expression_match(__attribute__((unused))w_expression_t * expression, __attribute__((unused))const char * str_test,
                               __attribute__((unused))const char ** end_match, regex_matching * regex_match);

void __wrap_w_calloc_expression_t(__attribute__((unused))w_expression_t ** var, w_exp_type_t type);

void __wrap_w_free_expression_t(__attribute__((unused))w_expression_t ** var);

bool __wrap_w_expression_compile(__attribute__((unused))w_expression_t * expression, __attribute__((unused))char * pattern,
                          __attribute__((unused))int flags);

#endif
