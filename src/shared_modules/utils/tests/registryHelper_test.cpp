/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 19, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifdef WIN32
#include "registryHelper_test.h"
#include "registryHelper.h"

constexpr auto CENTRAL_PROCESSOR_REGISTRY{"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"};

void RegistryUtilsTest::SetUp() {};

void RegistryUtilsTest::TearDown() {};

TEST_F(RegistryUtilsTest, RegistryString)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY);
    const auto result{reg.string("ProcessorNameString")};
    EXPECT_FALSE(result.empty());
}

TEST_F(RegistryUtilsTest, RegistryDWORD)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY);
    const auto result{reg.dword("~MHz")};
    EXPECT_NE(0, result);
}
#endif