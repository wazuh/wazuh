/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 18, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRYVALUE_TEST_H
#define _REGISTRYVALUE_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class RegistryValueTest : public testing::Test {
    protected:
        RegistryValueTest() = default;
        virtual ~RegistryValueTest() = default;

        void SetUp() override;
        void TearDown() override;
        fim_entry* fimEntryTest;
};

#endif //_REGISTRYVALUE_TEST_H
