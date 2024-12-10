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
#include <gtest/gtest.h>

#include <base/utils/evpHelper.hpp>

class EVPHelperTest : public ::testing::Test
{
protected:
    EVPHelperTest() = default;
    virtual ~EVPHelperTest() = default;
};

/**
 * @brief Test
 *
 */
TEST_F(EVPHelperTest, ValidEncryptionAndDecryption)
{
    std::vector<char> encryptedData;
    std::string inputData = "This is a test. This is a test.";
    base::utils::EVPHelper().encryptAES256(inputData, encryptedData);

    std::string decryptedData;

    EXPECT_NO_THROW(base::utils::EVPHelper().decryptAES256(encryptedData, decryptedData));
    ASSERT_EQ(decryptedData, inputData);
}
