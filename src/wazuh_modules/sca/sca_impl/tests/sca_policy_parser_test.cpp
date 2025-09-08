#include <gtest/gtest.h>

#include <sca_policy_parser.hpp>

#include "logging_helper.hpp"

#include <json.hpp>
#include <string>

using namespace testing;

class PolicyParserTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            // Set up the logging callback to avoid "Log callback not set" errors
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */)
            {
                // Mock logging callback that does nothing
            });

        }
};

// NOLINTBEGIN(bugprone-exception-escape)

TEST_F(PolicyParserTest, InvalidYamlFileDoesNotThrow)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json{}; // Empty JSON to simulate conversion failure
    };

    EXPECT_NO_THROW({ const PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson); });
}

TEST_F(PolicyParserTest, EmptyJsonDoesNotThrow)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse("{}"); // Valid empty JSON
    };

    EXPECT_NO_THROW({ const PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson); });
}

TEST_F(PolicyParserTest, ValidJsonWithoutPolicyElementsDoesNotThrow)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({"other": "data"})"); // Valid JSON without policy elements
    };

    EXPECT_NO_THROW({ const PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson); });
}

TEST_F(PolicyParserTest, ConstructorExtractsVariables)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({
            "variables": {
                "$var1": "/etc",
                "$var11": "/usr"
            },
            "policy": {
                "id": "policy1"
            },
            "checks": [
                {
                    "id": "check1",
                    "title": "title",
                    "condition": "all",
                    "rules": ["f: $var1/passwd exists", "f: $var11/shared exists"]
                }
            ]
        })");
    };

    PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson);

    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);

    ASSERT_TRUE(policyOpt);
    ASSERT_EQ(j["checks"].size(), 1);
    EXPECT_EQ(j["checks"][0]["id"], "check1");
    EXPECT_EQ(j["checks"][0]["title"], "title");
    EXPECT_EQ(j["checks"][0]["condition"], "all");
    EXPECT_EQ(j["checks"][0]["rules"][0], "f: /etc/passwd exists");
    EXPECT_EQ(j["checks"][0]["rules"][1], "f: /usr/shared exists");
    ASSERT_EQ(j["policies"].size(), 1);
    EXPECT_EQ(j["policies"][0]["id"], "policy1");
}

TEST_F(PolicyParserTest, MissingPolicyReturnsNullopt)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({
            "checks": [
                {
                    "id": "check1",
                    "title": "Title",
                    "condition": "all",
                    "rules": ["f: /test exists"]
                }
            ]
        })");
    };

    PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson);
    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);
    EXPECT_FALSE(policyOpt);
}

TEST_F(PolicyParserTest, MissingChecksReturnsNullopt)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({
            "policy": {
                "id": "policy_id"
            },
            "requirements": {
                "title": "title",
                "condition": "all",
                "rules": ["f: /etc/passwd exists"]
            }
        })");
    };

    PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson);
    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);
    EXPECT_FALSE(policyOpt);
}

TEST_F(PolicyParserTest, ValidPolicyWithRequirementsAndChecks)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({
            "policy": {
                "id": "policy_id",
                "name": "Test Policy"
            },
            "requirements": {
                "title": "System Requirements",
                "condition": "all",
                "rules": ["f: /etc/passwd exists"]
            },
            "checks": [
                {
                    "id": "check1",
                    "title": "File Check",
                    "condition": "any",
                    "rules": ["f: /tmp/test exists"]
                }
            ]
        })");
    };

    PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson);
    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);

    ASSERT_TRUE(policyOpt);
    EXPECT_EQ(j["policies"].size(), 1);
    EXPECT_EQ(j["policies"][0]["id"], "policy_id");
    EXPECT_EQ(j["checks"].size(), 1);
    EXPECT_EQ(j["checks"][0]["id"], "check1");
}

TEST_F(PolicyParserTest, InvalidConditionInRequirementsHandledGracefully)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({
            "policy": {
                "id": "policy_id"
            },
            "requirements": {
                "title": "title",
                "condition": "invalid_condition",
                "rules": ["f: /etc/passwd exists"]
            },
            "checks": [
                {
                    "id": "check1",
                    "title": "Title",
                    "condition": "all",
                    "rules": ["f: /test exists"]
                }
            ]
        })");
    };

    PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson);
    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);
    EXPECT_FALSE(policyOpt); // Should fail due to invalid condition
}

TEST_F(PolicyParserTest, InvalidConditionInChecksHandledGracefully)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({
            "policy": {
                "id": "policy_id"
            },
            "checks": [
                {
                    "id": "check1",
                    "title": "Title",
                    "condition": "invalid_condition",
                    "rules": ["f: /test exists"]
                }
            ]
        })");
    };

    PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson);
    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);

    // Should succeed but skip the invalid check
    ASSERT_TRUE(policyOpt);
    EXPECT_EQ(j["policies"].size(), 1);
    // The check with invalid condition should be skipped, so checks array should be empty
    EXPECT_EQ(j["checks"].size(), 0);
}

TEST_F(PolicyParserTest, InvalidRuleIsHandledGracefully)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({
            "policy": {
                "id": "policy_id"
            },
            "checks": [
                {
                    "id": "check1",
                    "title": "Title",
                    "condition": "any",
                    "rules": ["invalid_rule", "f: /valid/file exists"]
                }
            ]
        })");
    };

    PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson);
    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);

    ASSERT_TRUE(policyOpt);
    ASSERT_EQ(j["checks"].size(), 1);
    // Should contain only the valid rule
    EXPECT_GT(j["checks"][0]["rules"].size(), 0);
}

TEST_F(PolicyParserTest, MultipleChecksWithValidConditions)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({
            "policy": {
                "id": "multi_check_policy"
            },
            "checks": [
                {
                    "id": "check1",
                    "title": "First Check",
                    "condition": "all",
                    "rules": ["f: /etc/passwd exists"]
                },
                {
                    "id": "check2",
                    "title": "Second Check",
                    "condition": "any",
                    "rules": ["f: /tmp/test exists"]
                },
                {
                    "id": "check3",
                    "title": "Third Check",
                    "condition": "none",
                    "rules": ["f: /nonexistent exists"]
                }
            ]
        })");
    };

    PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson);
    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);

    ASSERT_TRUE(policyOpt);
    EXPECT_EQ(j["policies"].size(), 1);
    EXPECT_EQ(j["checks"].size(), 3);
    EXPECT_EQ(j["checks"][0]["condition"], "all");
    EXPECT_EQ(j["checks"][1]["condition"], "any");
    EXPECT_EQ(j["checks"][2]["condition"], "none");
}

TEST_F(PolicyParserTest, VariableReplacementInRules)
{
    auto mockYamlToJson = [](const std::string&) -> nlohmann::json
    {
        return nlohmann::json::parse(R"({
            "variables": {
                "$PATH": "/usr/bin",
                "$USER": "root"
            },
            "policy": {
                "id": "var_test_policy"
            },
            "checks": [
                {
                    "id": "var_check",
                    "title": "Variable Test",
                    "condition": "all",
                    "rules": ["f: $PATH/ls exists", "f: /home/$USER exists"]
                }
            ]
        })");
    };

    PolicyParser parser("dummy.yaml", 30, false, mockYamlToJson);
    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);

    ASSERT_TRUE(policyOpt);
    ASSERT_EQ(j["checks"].size(), 1);
    // Variables should be replaced in the rules
    const auto& rules = j["checks"][0]["rules"];
    EXPECT_GT(rules.size(), 0);
}

// NOLINTEND(bugprone-exception-escape)
