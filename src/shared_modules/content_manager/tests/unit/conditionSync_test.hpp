/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Dec 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONDITION_SYNC_TEST_HPP
#define _CONDITION_SYNC_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for ConditionSync
 */
class ConditionSyncTest : public ::testing::Test
{
protected:
    ConditionSyncTest() = default;
    ~ConditionSyncTest() override = default;
};

#endif //_CONDITION_SYNC_TEST_HPP
