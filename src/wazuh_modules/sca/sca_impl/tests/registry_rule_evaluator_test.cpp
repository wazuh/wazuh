#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

#include "logging_helper.hpp"

#include <filesystem>
#include <memory>
#include <stdexcept>
#include <system_error>

class RegistryRuleEvaluatorTest : public ::testing::Test
{
    protected:
        PolicyEvaluationContext m_ctx;
        RegistryRuleEvaluator::IsValidKeyFunc m_isValidKey;
        RegistryRuleEvaluator::EnumValuesFunc m_enumValues;
        RegistryRuleEvaluator::EnumKeysFunc m_enumKeys;
        RegistryRuleEvaluator::GetValueFunc m_getValue;

        void SetUp() override
        {
            // Set up the logging callback to avoid "Log callback not set" errors
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */)
            {
                // Mock logging callback that does nothing
            });

            m_isValidKey = [](const std::string&)
            {
                return true;
            };
            m_enumValues = [](const std::string&)
            {
                return std::vector<std::string> {};
            };
            m_enumKeys = [](const std::string&)
            {
                return std::vector<std::string> {};
            };
            m_getValue = [](const std::string&, const std::string&)
            {
                return std::string {};
            };
        }

        RegistryRuleEvaluator CreateEvaluator()
        {
            return {m_ctx, m_isValidKey, m_enumValues, m_enumKeys, m_getValue};
        }
};

TEST_F(RegistryRuleEvaluatorTest, NoPatternValidKeyReturnsFound)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "HKEY_LOCAL_MACHINE\\Software\\Something";
    m_isValidKey = [](const std::string&)
    {
        return true;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, NoPatternInvalidKeyReturnsNotFound)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "HKEY_LOCAL_MACHINE\\Software\\Missing";
    m_isValidKey = [](const std::string&)
    {
        return false;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorTest, NoPatternAndExceptionReturnsInvalid)
{
    m_ctx.pattern = std::nullopt;
    m_ctx.rule = "HKEY_LOCAL_MACHINE\\Software\\Something";
    m_isValidKey = [](const std::string&) -> bool
    {
        throw std::system_error(EDOM, std::generic_category(), "FIX ME");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(RegistryRuleEvaluatorTest, PatternAndExceptionReturnsInvalid)
{
    m_ctx.pattern = std::string("r:.*");
    m_ctx.rule = "HKEY_LOCAL_MACHINE\\Software\\Something";
    m_isValidKey = [](const std::string&) -> bool
    {
        throw std::system_error(EDOM, std::generic_category(), "FIX ME");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
}

TEST_F(RegistryRuleEvaluatorTest, PatternKeyFoundReturnsFound)
{
    m_ctx.pattern = std::string("ExpectedKey");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, PatternKeyNotFoundReturnsNotFound)
{
    m_ctx.pattern = std::string("MissingKey");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorTest, PatternRegexKeyFoundReturnsFound)
{
    m_ctx.pattern = std::string("r:ExpectedKey");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, PatternRegexKeyNotFoundReturnsNotFound)
{
    m_ctx.pattern = std::string("r:MissingKey");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorTest, PatternArrowValueFoundReturnsFound)
{
    m_ctx.pattern = std::string("ExpectedKey -> ExpectedValue");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&) -> std::string
    {
        return "ExpectedValue";
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, PatternArrowValueFoundReturnsFoundCaseInsensitive)
{
    m_ctx.pattern = std::string("expectedKey -> expectedValue");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&) -> std::string
    {
        return "ExpectedValue";
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, PatternArrowValueNotFoundReturnsNotFound)
{
    m_ctx.pattern = std::string("ExpectedKey -> MissingValue");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&) -> std::string
    {
        return "ExpectedValue";
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorTest, PatternArrowRegexValueFoundReturnsFound)
{
    m_ctx.pattern = std::string("ExpectedKey -> r:ExpectedValue");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&) -> std::string
    {
        return "ExpectedValue";
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, PatternArrowRegexValueNotFoundReturnsNotFound)
{
    m_ctx.pattern = std::string("ExpectedKey -> r:MissingValue");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&) -> std::string
    {
        return "ExpectedValue";
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorTest, KeyDoesNotExistHasReasonString)
{
    m_ctx.rule = "HKLM\\NonExistentKey";
    m_ctx.pattern = std::string("r:foo");

    m_isValidKey = [](const std::string&) -> bool
    {
        return false;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetInvalidReason().empty());
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("HKLM\\NonExistentKey"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("does not exist"));
}

TEST_F(RegistryRuleEvaluatorTest, KeyAccessExceptionHasReasonString)
{
    m_ctx.rule = "HKLM\\SomeKey";
    m_ctx.pattern = std::string("r:foo");

    m_isValidKey = [](const std::string&) -> bool
    {
        throw std::runtime_error("Access denied to registry");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetInvalidReason().empty());
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("HKLM\\SomeKey"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("Exception accessing registry"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("Access denied to registry"));
}

TEST_F(RegistryRuleEvaluatorTest, ValueDoesNotExistHasReasonString)
{
    m_ctx.rule = "HKLM\\SomeKey";
    m_ctx.pattern = std::string("NonExistentValue -> SomeContent");

    m_isValidKey = [](const std::string&) -> bool
    {
        return true;
    };

    m_getValue = [](const std::string&, const std::string&) -> std::optional<std::string>
    {
        return std::nullopt;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetInvalidReason().empty());
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("NonExistentValue"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("HKLM\\SomeKey"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("does not exist"));
}

TEST_F(RegistryRuleEvaluatorTest, KeyExistenceCheckExceptionHasReasonString)
{
    m_ctx.rule = "HKLM\\SomeKey";

    m_isValidKey = [](const std::string&) -> bool
    {
        throw std::runtime_error("Registry access error");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetInvalidReason().empty());
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("HKLM\\SomeKey"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("Exception checking registry key existence"));
    EXPECT_THAT(evaluator.GetInvalidReason(), ::testing::HasSubstr("Registry access error"));
}
