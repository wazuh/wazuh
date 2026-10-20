/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
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
