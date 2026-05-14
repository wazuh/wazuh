/*
 * Wazuh content manager - Component Tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 26, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_MODULE_TEST_HPP
#define _CONTENT_MODULE_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs component tests for ContentModule
 */
class ContentModuleTest : public ::testing::Test
{
protected:
    ContentModuleTest() = default;
    ~ContentModuleTest() override = default;
};

#endif //_CONTENT_MODULE_TEST_HPP
