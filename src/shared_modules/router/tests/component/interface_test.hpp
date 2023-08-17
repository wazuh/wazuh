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
 * @brief RouterInterfaceTest
 *
 */
class RouterInterfaceTest : public ::testing::Test
{
protected:
    RouterInterfaceTest() = default;
    ~RouterInterfaceTest() override = default;

    /**
     * @brief SetUp
     *
     */
    void SetUp() override;

    /**
     * @brief TearDown
     *
     */
    void TearDown() override;
};
#endif //_ROUTER_INTERFACE_TESTS_HPP
