/*
 * Wazuh content manager - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_CONTENT_UPDATER_TEST_HPP
#define _FACTORY_CONTENT_UPDATER_TEST_HPP

#include "gtest/gtest.h"

/**
 * @brief Runs unit tests for FactoryContentUpdater
 */
class FactoryContentUpdaterTest : public ::testing::Test
{
protected:
    FactoryContentUpdaterTest() = default;
    ~FactoryContentUpdaterTest() override = default;
};

#endif //_FACTORY_CONTENT_UPDATER_TEST_HPP
