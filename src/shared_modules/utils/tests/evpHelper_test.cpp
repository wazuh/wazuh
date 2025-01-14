/*
 * Wazuh - Shared Modules utils tests
 * Copyright (C) 2015, Wazuh Inc.
 * July 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "evpHelper_test.hpp"
#include "evpHelper.hpp"
#include "gtest/gtest.h"

/**
 * @brief Test
 *
 */
TEST_F(EVPHelperTest, ValidEncryptionAndDecryption)
{
    std::vector<char> encryptedData;
    std::string inputData = "This is a test. This is a test.";
    EVPHelper().encryptAES256(inputData, encryptedData);

    std::string decryptedData;

    EXPECT_NO_THROW(EVPHelper().decryptAES256(encryptedData, decryptedData));
    ASSERT_EQ(decryptedData, inputData);
}

