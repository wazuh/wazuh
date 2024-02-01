/*
 * Wazuh Content Manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 29, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _COMPONENTS_HELPER_TEST_HPP
#define _COMPONENTS_HELPER_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for APIDownloader
 *
 */
class ComponentsHelperTest : public ::testing::Test
{
protected:
    ComponentsHelperTest() = default;
    ~ComponentsHelperTest() override = default;
};

#endif //_COMPONENTS_HELPER_TEST_HPP
