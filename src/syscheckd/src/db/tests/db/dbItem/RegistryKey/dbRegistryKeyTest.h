/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * October 15, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRYKEY_TEST_H
#define _REGISTRYKEY_TEST_H
#include "gmock/gmock.h"
#include "gtest/gtest.h"

class RegistryKeyTest : public testing::Test
{
protected:
    RegistryKeyTest() = default;
    virtual ~RegistryKeyTest() = default;

    void SetUp() override;
    void TearDown() override;
    fim_entry* fimEntryTest;
    const nlohmann::json expectedValue = R"(
            {
                "data":[{"architecture":"[x64]","checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a","gid":"0","group_":"root",
                "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE","permissions":"-rw-rw-r--",
                "uid":"0", "owner":"fakeUser"}],"table":"registry_key"
            }
        )"_json;

    const nlohmann::json inputJson = R"(
        {
            "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":"0", "group_":"root", "architecture":1,
            "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "permissions":"-rw-rw-r--",
            "uid":"0", "owner":"fakeUser"
        }
    )"_json;
};

#endif //_REGISTRYKEY_TEST_H
