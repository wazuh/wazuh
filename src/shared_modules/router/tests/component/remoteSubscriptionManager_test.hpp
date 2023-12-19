/*
 * Wazuh router - RemoteStateHelper tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 06, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTE_STATE_HELPER_TEST_HPP
#define _REMOTE_STATE_HELPER_TEST_HPP

#include "routerModule.hpp"
#include <gtest/gtest.h>

/**
 * @brief Runs unit tests for RemoteStateHelper class
 */
class RemoteStateHelperTest : public ::testing::Test
{
protected:
    RemoteStateHelperTest() = default;
    ~RemoteStateHelperTest() override = default;

    /**
     * @brief Test setup routine.
     *
     */
    void SetUp() override
    {
        RouterModule::instance().start();
    }

    /**
     * @brief Test teardown routine.
     *
     */
    void TearDown() override
    {
        RouterModule::instance().stop();
    };
};

#endif //_REMOTE_STATE_HELPER_TEST_HPP
