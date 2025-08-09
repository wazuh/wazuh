#include <gtest/gtest.h>

#include "mocks/mock_yaml_document.hpp"
#include <sca_policy_parser.hpp>
#include <yaml_document.hpp>

#include "logging_helper.hpp"

#include <string>

using namespace testing;

class PolicyParserTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Set up the logging callback to avoid "Log callback not set" errors
        LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {
            // Mock logging callback that does nothing
        });

    }
};

// NOLINTBEGIN(bugprone-exception-escape)

TEST_F(PolicyParserTest, InvalidYamlFileNotThrows)
{
    auto mockYamlDocument = std::make_unique<MockYamlDocument>();
    MockYamlDocument* mockDocPtr = mockYamlDocument.get();

    EXPECT_CALL(*mockDocPtr, IsValidDocument()).WillOnce(::testing::Return(false));
    const std::filesystem::path path("dummy.yaml");
    EXPECT_NO_THROW({ const PolicyParser parser(path, 30, false, std::move(mockYamlDocument)); });
}

TEST_F(PolicyParserTest, YamlSequenceIsValid)
{
    auto yamlDocument = std::make_unique<YamlDocument>(std::string("- item1\n- item2"));

    const std::filesystem::path path("dummy.yaml");
    EXPECT_NO_THROW({ const PolicyParser parser(path, 30, false, std::move(yamlDocument)); });
}

TEST_F(PolicyParserTest, YamlMapIsValid)
{
    auto yamlDocument = std::make_unique<YamlDocument>(std::string("key: value"));

    const std::filesystem::path path("dummy.yaml");
    EXPECT_NO_THROW({ const PolicyParser parser(path, 30, false, std::move(yamlDocument)); }); // Maps are valid top-level YAML
}

TEST_F(PolicyParserTest, ConstructorExtractsVariables)
{
    const std::string yml = R"(
      variables:
        $var1: /etc
        $var11: /usr
      policy:
        id: policy1
      checks:
        - id: check1
          title: "title"
          condition: "all"
          rules:
            - 'f: $var1/passwd exists'
            - 'f: $var11/shared exists'
      )";

    auto yamlDocument = std::make_unique<YamlDocument>(yml);

    const std::filesystem::path path("dummy.yaml");
    PolicyParser parser(path, 30, false, std::move(yamlDocument));

    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);

    ASSERT_TRUE(policyOpt);
    ASSERT_EQ(j["checks"].size(), 1);
    EXPECT_EQ(j["checks"][0]["id"], "check1");
    EXPECT_EQ(j["checks"][0]["title"], "title");
    EXPECT_EQ(j["checks"][0]["condition"], "all");
    EXPECT_EQ(j["checks"][0]["rules"], "f: /etc/passwd exists, f: /usr/shared exists");

    ASSERT_EQ(j["policies"].size(), 1);
    EXPECT_EQ(j["policies"][0]["id"], "policy1");
}

TEST_F(PolicyParserTest, MissingPolicyReturnsNullopt)
{
    const std::string yml = R"(
      checks:
        - id: check1
          title: Title
          condition: all
          rules: ['f: /test exists']
      )";

    auto yamlDocument = std::make_unique<YamlDocument>(yml);

    const std::filesystem::path path("dummy.yaml");
    PolicyParser parser(path, 30, false, std::move(yamlDocument));
    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);
    EXPECT_FALSE(policyOpt);
}

TEST_F(PolicyParserTest, EmptyRequirementsReturnsNullopt)
{
    const std::string yml = R"(
      policy:
        id: test_policy
      requirements:
        title: "req title"
      )";

    const std::filesystem::path path("dummy.yaml");
    auto yamlDocument = std::make_unique<YamlDocument>(yml);
    PolicyParser parser(path, 30, false, std::move(yamlDocument));

    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);
    EXPECT_FALSE(policyOpt);
}

TEST_F(PolicyParserTest, MissingChecksReturnsNullopt)
{
    const std::string yml = R"(
      policy:
        id: policy_id
      requirements:
        title: title
        condition: all
        rules: ['f: /etc/passwd exists']
      )";

    const std::filesystem::path path("dummy.yaml");
    auto yamlDocument = std::make_unique<YamlDocument>(yml);
    PolicyParser parser(path, 30, false, std::move(yamlDocument));

    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);
    EXPECT_FALSE(policyOpt);
}

TEST_F(PolicyParserTest, InvalidConditionReturnsNullopt)
{
    const std::string yml = R"(
      policy:
        id: policy_id
      requirements:
        title: title
        condition: invalid_condition
        rules: ['f: /etc/passwd exists']
      )";

    const std::filesystem::path path("dummy.yaml");
    auto yamlDocument = std::make_unique<YamlDocument>(yml);
    PolicyParser parser(path, 30, false, std::move(yamlDocument));

    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);
    EXPECT_FALSE(policyOpt);
}

TEST_F(PolicyParserTest, InvalidRuleIsHandledGracefully)
{
    const std::string yml = R"(
      policy:
        id: policy_id
      checks:
        - id: "check1"
          title: "Title"
          condition: any
          rules:
            - "invalid_rule"
      )";

    const std::filesystem::path path("dummy.yaml");
    auto yamlDocument = std::make_unique<YamlDocument>(yml);
    PolicyParser parser(path, 30, false, std::move(yamlDocument));

    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);

    ASSERT_TRUE(policyOpt);
    ASSERT_EQ(j["checks"].size(), 1);
    EXPECT_EQ(j["checks"][0]["rules"], "");
}

TEST_F(PolicyParserTest, YamlNodeToJsonParsesMapWithSequenceValues)
{
    const std::string yml = R"(
      policy:
        id: policy_1
      checks:
        - id: "check1"
          title: "Complex check"
          condition: any
          rules:
            - "f: /tmp/test exists"
          metadata:
            tags:
              - category:
                  - security
                  - compliance
            platforms:
              - os:
                  - linux
                  - windows

      )";

    const std::filesystem::path path("dummy.yaml");
    auto yamlDocument = std::make_unique<YamlDocument>(yml);
    PolicyParser parser(path, 30, false, std::move(yamlDocument));

    nlohmann::json j;
    const auto policyOpt = parser.ParsePolicy(j);

    ASSERT_TRUE(policyOpt);
    EXPECT_EQ(j["checks"][0]["metadata"]["tags"], "category:security, category:compliance");
    EXPECT_EQ(j["checks"][0]["metadata"]["platforms"], "os:linux, os:windows");
}

// NOLINTEND(bugprone-exception-escape)
