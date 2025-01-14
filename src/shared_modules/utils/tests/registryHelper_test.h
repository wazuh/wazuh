/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef REGISTRY_HELPER_TESTS_H
#define REGISTRY_HELPER_TESTS_H
#include "gtest/gtest.h"

class RegistryUtilsTest : public ::testing::Test
{
    protected:

        RegistryUtilsTest() = default;
        virtual ~RegistryUtilsTest() = default;

        void SetUp() override;
        void TearDown() override;
};
#endif //REGISTRY_HELPER_TESTS_H
