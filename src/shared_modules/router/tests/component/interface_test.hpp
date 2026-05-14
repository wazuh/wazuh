/*
 * Wazuh router - Interface tests
 * Copyright (C) 2015, Wazuh Inc.
 * Apr 29, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_INTERFACE_TESTS_HPP
#define _ROUTER_INTERFACE_TESTS_HPP

#include <gtest/gtest.h>

/**
 * @brief RouterInterfaceTest class.
 *
 */
class RouterInterfaceTest : public ::testing::Test
{
protected:
    RouterInterfaceTest() = default;
    ~RouterInterfaceTest() override = default;

    /**
     * @brief Test setup routine.
     *
     */
    void SetUp() override;

    /**
     * @brief Test teardown routine.
     *
     */
    void TearDown() override;
};

/**
 * @brief RouterInterfaceTestNoBroker class with no SetUp.
 *
 */
class RouterInterfaceTestNoBroker : public ::testing::Test
{
protected:
    RouterInterfaceTestNoBroker() = default;
    ~RouterInterfaceTestNoBroker() override = default;

    /**
     * @brief Test setup routine.
     *
     */
    void SetUp() override {};

    /**
     * @brief Test teardown routine.
     *
     */
    void TearDown() override {};
};

#endif //_ROUTER_INTERFACE_TESTS_HPP
