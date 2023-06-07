/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _EXECUTION_CONTEXT_TEST_HPP
#define _EXECUTION_CONTEXT_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for ExecutionContext
 */
class ExecutionContextTest : public ::testing::Test
{
protected:
    ExecutionContextTest() = default;
    ~ExecutionContextTest() override = default;
};

#endif //_EXECUTION_CONTEXT_TEST_HPP
