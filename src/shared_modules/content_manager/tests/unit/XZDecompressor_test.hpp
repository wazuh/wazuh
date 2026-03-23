/*
 * Wazuh Content Manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Jun 07, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _XZ_DECOMPRESSOR_TEST_HPP
#define _XZ_DECOMPRESSOR_TEST_HPP

#include "conditionSync.hpp"
#include "updaterContext.hpp"
#include "gtest/gtest.h"
#include <memory>

/**
 * @brief Runs unit tests for XZDecompressor
 */
class XZDecompressorTest : public ::testing::Test
{
protected:
    XZDecompressorTest() = default;
    ~XZDecompressorTest() override = default;

    std::shared_ptr<ConditionSync> m_spStopActionCondition {
        std::make_shared<ConditionSync>(false)}; ///< Stop condition wrapper.

    std::shared_ptr<UpdaterContext> m_spUpdaterContext; ///< Context used on tests.

    /**
     * @brief Setup routine for each test fixture.
     *
     */
    void SetUp() override;

    /**
     * @brief Teardown routine for each test fixture.
     *
     */
    void TearDown() override;
};

#endif //_XZ_DECOMPRESSOR_TEST_HPP
