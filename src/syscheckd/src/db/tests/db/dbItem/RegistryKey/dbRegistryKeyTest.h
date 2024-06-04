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
#include "gtest/gtest.h"
#include "gmock/gmock.h"

class RegistryKeyTest : public testing::Test {
    protected:
        RegistryKeyTest() = default;
        virtual ~RegistryKeyTest() = default;

        void SetUp() override;
        void TearDown() override;
        fim_entry* fimEntryTest;
        const nlohmann::json expectedValue = R"(
            {
                "data":[{"arch":"[x64]","checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a","gid":"0","group_name":"root",
                "hash_full_path":"00a7ee53218b25b5364c8773f37a38c93eae3880","last_event":1596489275,"mtime":1578075431,
                "path":"HKEY_LOCAL_MACHINE\\SOFTWARE","perm":"-rw-rw-r--",
                "scanned":1,"uid":"0", "user_name":"fakeUser"}],"table":"registry_key"
            }
        )"_json;

        const nlohmann::json inputJson = R"(
        {
            "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "gid":"0", "group_name":"root", "arch":1,
            "last_event":1596489275, "mode":0, "mtime":1578075431, "path":"HKEY_LOCAL_MACHINE\\SOFTWARE", "perm":"-rw-rw-r--",
            "scanned":1, "uid":"0", "user_name":"fakeUser", "hash_full_path":"00a7ee53218b25b5364c8773f37a38c93eae3880"
        }
    )"_json;
};

#endif //_REGISTRYKEY_TEST_H
