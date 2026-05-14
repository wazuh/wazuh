/*
 * Wazuh router - RemoteSubscriptionManager tests
 * Copyright (C) 2015, Wazuh Inc.
 * December 19, 2023.
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
 * @brief Runs unit tests for RemoteSubscriptionManager class
 */
class RemoteSubscriptionManagerTest : public ::testing::Test
{
protected:
    RemoteSubscriptionManagerTest() = default;
    ~RemoteSubscriptionManagerTest() override = default;

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
