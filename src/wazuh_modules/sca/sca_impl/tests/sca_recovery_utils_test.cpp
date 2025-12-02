/*
 * Wazuh SCA
 * Copyright (C) 2015, Wazuh Inc.
 * December 1, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include <sca_recovery_utils.hpp>
#include <mock_dbsync.hpp>

class SCARecoveryUtilsTest : public ::testing::Test
{
    protected:
        void SetUp() override {}
        void TearDown() override {}
};

// Tests for escapeSqlString
TEST_F(SCARecoveryUtilsTest, EscapeSqlStringNoQuotes)
{
    auto result = sca::recovery::escapeSqlString("normal_string");
    EXPECT_EQ(result, "normal_string");
}

TEST_F(SCARecoveryUtilsTest, EscapeSqlStringSingleQuote)
{
    auto result = sca::recovery::escapeSqlString("test'value");
    EXPECT_EQ(result, "test''value");
}

TEST_F(SCARecoveryUtilsTest, EscapeSqlStringMultipleQuotes)
{
    auto result = sca::recovery::escapeSqlString("test'value'with'quotes");
    EXPECT_EQ(result, "test''value''with''quotes");
}

TEST_F(SCARecoveryUtilsTest, EscapeSqlStringEmptyString)
{
    auto result = sca::recovery::escapeSqlString("");
    EXPECT_EQ(result, "");
}

TEST_F(SCARecoveryUtilsTest, EscapeSqlStringOnlyQuote)
{
    auto result = sca::recovery::escapeSqlString("'");
    EXPECT_EQ(result, "''");
}

// Tests for stringToJsonArray
TEST_F(SCARecoveryUtilsTest, StringToJsonArrayEmptyString)
{
    auto result = sca::recovery::stringToJsonArray("");
    EXPECT_TRUE(result.is_array());
    EXPECT_TRUE(result.empty());
}

TEST_F(SCARecoveryUtilsTest, StringToJsonArraySingleValue)
{
    auto result = sca::recovery::stringToJsonArray("value1");
    EXPECT_TRUE(result.is_array());
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0], "value1");
}

TEST_F(SCARecoveryUtilsTest, StringToJsonArrayMultipleValues)
{
    auto result = sca::recovery::stringToJsonArray("value1,value2,value3");
    EXPECT_TRUE(result.is_array());
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "value1");
    EXPECT_EQ(result[1], "value2");
    EXPECT_EQ(result[2], "value3");
}

TEST_F(SCARecoveryUtilsTest, StringToJsonArrayWithSpaces)
{
    auto result = sca::recovery::stringToJsonArray("  value1  , value2 ,  value3  ");
    EXPECT_TRUE(result.is_array());
    EXPECT_EQ(result.size(), 3);
    EXPECT_EQ(result[0], "value1");
    EXPECT_EQ(result[1], "value2");
    EXPECT_EQ(result[2], "value3");
}

TEST_F(SCARecoveryUtilsTest, StringToJsonArrayWithEmptyTokens)
{
    auto result = sca::recovery::stringToJsonArray("value1,,value3");
    EXPECT_TRUE(result.is_array());
    EXPECT_EQ(result.size(), 2);
    EXPECT_EQ(result[0], "value1");
    EXPECT_EQ(result[1], "value3");
}

// Tests for normalizeCheckForStateful
TEST_F(SCARecoveryUtilsTest, NormalizeCheckConvertRefs)
{
    nlohmann::json check = {{"refs", "ref1,ref2"}, {"id", "123"}};
    sca::recovery::normalizeCheckForStateful(check);

    EXPECT_FALSE(check.contains("refs"));
    EXPECT_TRUE(check.contains("references"));
    EXPECT_EQ(check["references"].size(), 2);
    EXPECT_EQ(check["references"][0], "ref1");
    EXPECT_EQ(check["references"][1], "ref2");
}

TEST_F(SCARecoveryUtilsTest, NormalizeCheckConvertCompliance)
{
    nlohmann::json check = {{"compliance", "cis,pci"}, {"id", "123"}};
    sca::recovery::normalizeCheckForStateful(check);

    EXPECT_TRUE(check.contains("compliance"));
    EXPECT_EQ(check["compliance"].size(), 2);
    EXPECT_EQ(check["compliance"][0], "cis");
    EXPECT_EQ(check["compliance"][1], "pci");
}

TEST_F(SCARecoveryUtilsTest, NormalizeCheckConvertRules)
{
    nlohmann::json check = {{"rules", "rule1,rule2,rule3"}, {"id", "123"}};
    sca::recovery::normalizeCheckForStateful(check);

    EXPECT_TRUE(check.contains("rules"));
    EXPECT_EQ(check["rules"].size(), 3);
}

TEST_F(SCARecoveryUtilsTest, NormalizeCheckRemovePolicyId)
{
    nlohmann::json check = {{"policy_id", "policy1"}, {"id", "123"}};
    sca::recovery::normalizeCheckForStateful(check);

    EXPECT_FALSE(check.contains("policy_id"));
}

TEST_F(SCARecoveryUtilsTest, NormalizeCheckAllTransformations)
{
    nlohmann::json check =
    {
        {"refs", "ref1,ref2"},
        {"compliance", "cis"},
        {"rules", "rule1"},
        {"policy_id", "policy1"},
        {"id", "123"},
        {"name", "Test Check"}
    };
    sca::recovery::normalizeCheckForStateful(check);

    EXPECT_FALSE(check.contains("refs"));
    EXPECT_TRUE(check.contains("references"));
    EXPECT_FALSE(check.contains("policy_id"));
    EXPECT_TRUE(check.contains("id"));
    EXPECT_TRUE(check.contains("name"));
}

// Tests for normalizePolicyForStateful
TEST_F(SCARecoveryUtilsTest, NormalizePolicyConvertRefs)
{
    nlohmann::json policy = {{"refs", "ref1,ref2"}, {"id", "policy1"}};
    sca::recovery::normalizePolicyForStateful(policy);

    EXPECT_FALSE(policy.contains("refs"));
    EXPECT_TRUE(policy.contains("references"));
    EXPECT_EQ(policy["references"].size(), 2);
}

TEST_F(SCARecoveryUtilsTest, NormalizePolicyNoRefs)
{
    nlohmann::json policy = {{"id", "policy1"}, {"name", "Test Policy"}};
    sca::recovery::normalizePolicyForStateful(policy);

    EXPECT_FALSE(policy.contains("refs"));
    EXPECT_FALSE(policy.contains("references"));
    EXPECT_TRUE(policy.contains("id"));
    EXPECT_TRUE(policy.contains("name"));
}

// Tests for getPolicyById
TEST_F(SCARecoveryUtilsTest, GetPolicyByIdNullDbSync)
{
    auto result = sca::recovery::getPolicyById("policy1", nullptr);
    EXPECT_TRUE(result.empty());
}

TEST_F(SCARecoveryUtilsTest, GetPolicyByIdFound)
{
    auto mockDBSync = std::make_shared<MockDBSync>();

    EXPECT_CALL(*mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Invoke([](const nlohmann::json& /* query */,
                                   std::function<void(ReturnTypeCallback, const nlohmann::json&)> callback)
    {
        nlohmann::json policy =
        {
            {"id", "policy1"},
            {"name", "Test Policy"},
            {"description", "A test policy"},
            {"file", "/path/to/policy.yml"},
            {"refs", "ref1"}
        };
        callback(SELECTED, policy);
    }));

    auto result = sca::recovery::getPolicyById("policy1", mockDBSync);

    EXPECT_FALSE(result.empty());
    EXPECT_EQ(result["id"], "policy1");
    EXPECT_EQ(result["name"], "Test Policy");
}

TEST_F(SCARecoveryUtilsTest, GetPolicyByIdNotFound)
{
    auto mockDBSync = std::make_shared<MockDBSync>();

    EXPECT_CALL(*mockDBSync, selectRows(::testing::_, ::testing::_))
    .WillOnce(::testing::Return());

    auto result = sca::recovery::getPolicyById("nonexistent", mockDBSync);
    EXPECT_TRUE(result.empty());
}

// Tests for buildStatefulMessage
TEST_F(SCARecoveryUtilsTest, BuildStatefulMessageBasic)
{
    nlohmann::json check =
    {
        {"id", "check1"},
        {"checksum", "abc123"},
        {"version", 5},
        {"name", "Test Check"}
    };
    nlohmann::json policy =
    {
        {"id", "policy1"},
        {"name", "Test Policy"}
    };

    auto result = sca::recovery::buildStatefulMessage(check, policy);

    // Verify structure
    EXPECT_TRUE(result.contains("checksum"));
    EXPECT_TRUE(result.contains("check"));
    EXPECT_TRUE(result.contains("policy"));
    EXPECT_TRUE(result.contains("state"));

    // Verify checksum restructuring
    EXPECT_TRUE(result["checksum"].contains("hash"));
    EXPECT_TRUE(result["checksum"]["hash"].contains("sha1"));
    EXPECT_EQ(result["checksum"]["hash"]["sha1"], "abc123");

    // Verify state
    EXPECT_TRUE(result["state"].contains("modified_at"));
    EXPECT_TRUE(result["state"].contains("document_version"));
    EXPECT_EQ(result["state"]["document_version"], 5);

    // Verify check doesn't have checksum or version anymore
    EXPECT_FALSE(result["check"].contains("checksum"));
    EXPECT_FALSE(result["check"].contains("version"));
}

TEST_F(SCARecoveryUtilsTest, BuildStatefulMessageWithNormalization)
{
    nlohmann::json check =
    {
        {"id", "check1"},
        {"checksum", "abc123"},
        {"version", 1},
        {"refs", "ref1,ref2"},
        {"compliance", "cis,pci"},
        {"rules", "rule1"},
        {"policy_id", "policy1"}
    };
    nlohmann::json policy =
    {
        {"id", "policy1"},
        {"refs", "policy_ref1"}
    };

    auto result = sca::recovery::buildStatefulMessage(check, policy);

    // Verify check normalization
    EXPECT_FALSE(result["check"].contains("refs"));
    EXPECT_TRUE(result["check"].contains("references"));
    EXPECT_FALSE(result["check"].contains("policy_id"));

    // Verify policy normalization
    EXPECT_FALSE(result["policy"].contains("refs"));
    EXPECT_TRUE(result["policy"].contains("references"));
}

TEST_F(SCARecoveryUtilsTest, BuildStatefulMessageEmptyChecksum)
{
    nlohmann::json check =
    {
        {"id", "check1"},
        {"checksum", ""},
        {"version", 1}
    };
    nlohmann::json policy = {{"id", "policy1"}};

    auto result = sca::recovery::buildStatefulMessage(check, policy);

    // Empty checksum should result in empty checksum object
    EXPECT_TRUE(result["checksum"].empty());
}

TEST_F(SCARecoveryUtilsTest, BuildStatefulMessageNoVersion)
{
    nlohmann::json check =
    {
        {"id", "check1"},
        {"checksum", "abc123"}
    };
    nlohmann::json policy = {{"id", "policy1"}};

    auto result = sca::recovery::buildStatefulMessage(check, policy);

    // State should still have modified_at but no document_version
    EXPECT_TRUE(result["state"].contains("modified_at"));
    EXPECT_FALSE(result["state"].contains("document_version"));
}
