/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
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

constexpr auto CENTRAL_PROCESSOR_REGISTRY{"HARDWARE\\DESCRIPTION\\System\\CentralProcessor"};
constexpr auto CENTRAL_PROCESSOR_REGISTRY_0{"HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"};

void RegistryUtilsTest::SetUp() {};

void RegistryUtilsTest::TearDown() {};

TEST_F(RegistryUtilsTest, RegistryString)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);
    const auto result{reg.string("ProcessorNameString")};
    EXPECT_FALSE(result.empty());
}

TEST_F(RegistryUtilsTest, RegistryStringNoThrow)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);
    std::string value;
    const auto result{reg.string("SomeWrongValue", value)};
    EXPECT_TRUE(value.empty());
    EXPECT_FALSE(result);
}

TEST_F(RegistryUtilsTest, RegistryDWORD)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);
    const auto result{reg.dword("~MHz")};
    EXPECT_NE(0u, result);
}

TEST_F(RegistryUtilsTest, RegistryDWORDNoThrow)
{
    DWORD value{0};
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0);
    const auto result{reg.dword("SomeWrongValue", value)};
    EXPECT_FALSE(result);
}

TEST_F(RegistryUtilsTest, RegistryEnumerate)
{
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY, KEY_ENUMERATE_SUB_KEYS | KEY_READ);
    const auto result{reg.enumerate()};
    EXPECT_NE(0u, result.size());
}

TEST_F(RegistryUtilsTest, RegistryEnumerateNoThrow)
{
    std::vector<std::string> values;
    Utils::Registry reg(HKEY_LOCAL_MACHINE, CENTRAL_PROCESSOR_REGISTRY_0, KEY_ENUMERATE_SUB_KEYS | KEY_READ);
    reg.enumerate(values);
    EXPECT_EQ(0u, values.size());
}

#endif