/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
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
        const nlohmann::json inputJson = R"(
            {
                "checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a", "type":0, "size":4925, "name":"testRegistry",
                "last_event":1596489275, "mode":0, "hash_md5":"4b531524aa13c8a54614100b570b3dc7",
                "hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
                "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a", "scanned":1,
                "path":"pathTestRegistry", "arch":0, "hash_full_path":"00a7ee53218b25b5364c8773f37a38c93eae3880"

            }
        )"_json;

        const nlohmann::json expectedValue = R"(
            {
            "data":[{"arch":"[x32]","checksum":"a2fbef8f81af27155dcee5e3927ff6243593b91a","hash_md5":"4b531524aa13c8a54614100b570b3dc7",
            "hash_full_path":"00a7ee53218b25b5364c8773f37a38c93eae3880","hash_sha1":"7902feb66d0bcbe4eb88e1bfacf28befc38bd58b",
            "hash_sha256":"e403b83dd73a41b286f8db2ee36d6b0ea6e80b49f02c476e0a20b4181a3a062a","last_event":1596489275,
            "name":"testRegistry","path":"pathTestRegistry","scanned":1,"size":4925,"type":0}],"table":"registry_data"
            }
        )"_json;
};

#endif //_REGISTRYVALUE_TEST_H
