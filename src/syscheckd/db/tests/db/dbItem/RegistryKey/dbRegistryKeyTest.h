/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 15, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRYKEY_TEST_H
#define _REGISTRYKEY_TEST_H
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class RegistryKeyTest : public testing::Test {
    protected:
        RegistryKeyTest() = default;
        virtual ~RegistryKeyTest() = default;

        void SetUp() override;
        void TearDown() override;
        fim_entry* fimEntryTest;
};

#endif //_REGISTRYKEY_TEST_H
