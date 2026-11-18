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

            m_isValidKey = [](const std::string&, RegistryView)
            {
                return true;
            };
            m_enumValues = [](const std::string&, RegistryView)
            {
                return std::vector<std::string> {};
            };
            m_enumKeys = [](const std::string&, RegistryView)
            {
                return std::vector<std::string> {};
            };
            m_getValue = [](const std::string&, const std::string&, RegistryView)
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
    m_isValidKey = [](const std::string&, RegistryView)
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
    m_isValidKey = [](const std::string&, RegistryView)
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
    m_isValidKey = [](const std::string&, RegistryView) -> bool
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
    m_isValidKey = [](const std::string&, RegistryView) -> bool
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

    m_enumValues = [](const std::string&, RegistryView)
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

    m_enumValues = [](const std::string&, RegistryView)
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

    m_enumValues = [](const std::string&, RegistryView)
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

    m_enumValues = [](const std::string&, RegistryView)
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

    m_enumValues = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::string
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

    m_enumValues = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::string
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

    m_enumValues = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::string
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

    m_enumValues = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::string
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

    m_enumValues = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::string
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

    m_isValidKey = [](const std::string&, RegistryView) -> bool
    {
        return false;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("HKLM\\NonExistentKey"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("does not exist"));
}

TEST_F(RegistryRuleEvaluatorTest, KeyAccessExceptionHasReasonString)
{
    m_ctx.rule = "HKLM\\SomeKey";
    m_ctx.pattern = std::string("r:foo");

    m_isValidKey = [](const std::string&, RegistryView) -> bool
    {
        throw std::runtime_error("Access denied to registry");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("HKLM\\SomeKey"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Exception accessing registry"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Access denied to registry"));
}

TEST_F(RegistryRuleEvaluatorTest, ValueDoesNotExistHasReasonString)
{
    m_ctx.rule = "HKLM\\SomeKey";
    m_ctx.pattern = std::string("NonExistentValue -> SomeContent");

    m_isValidKey = [](const std::string&, RegistryView) -> bool
    {
        return true;
    };

    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::optional<std::string>
    {
        return std::nullopt;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("NonExistentValue"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("HKLM\\SomeKey"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("does not exist"));
}

TEST_F(RegistryRuleEvaluatorTest, KeyExistenceCheckExceptionHasReasonString)
{
    m_ctx.rule = "HKLM\\SomeKey";

    m_isValidKey = [](const std::string&, RegistryView) -> bool
    {
        throw std::runtime_error("Registry access error");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("HKLM\\SomeKey"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Exception checking registry key existence"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Registry access error"));
}

TEST_F(RegistryRuleEvaluatorTest, KeyOnlyIn64BitViewReturnsFound)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Only64";
    std::vector<RegistryView> queried;

    m_isValidKey = [&queried](const std::string&, RegistryView view)
    {
        queried.push_back(view);
        return view == RegistryView::Bits64;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
    // Found in the 64-bit view, so the 32-bit view is not consulted
    EXPECT_EQ(queried, std::vector<RegistryView> {RegistryView::Bits64});
}

TEST_F(RegistryRuleEvaluatorTest, KeyOnlyIn32BitViewReturnsFound)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Only32";
    std::vector<RegistryView> queried;

    m_isValidKey = [&queried](const std::string&, RegistryView view)
    {
        queried.push_back(view);
        return view == RegistryView::Bits32;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
    EXPECT_EQ(queried, (std::vector<RegistryView> {RegistryView::Bits64, RegistryView::Bits32}));
}

TEST_F(RegistryRuleEvaluatorTest, KeyInNoViewReturnsNotFound)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Missing";

    m_isValidKey = [](const std::string&, RegistryView)
    {
        return false;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
    EXPECT_TRUE(evaluator.GetUnresolvedReason().empty());
}

TEST_F(RegistryRuleEvaluatorTest, NegatedKeyOnlyIn64BitViewReturnsNotFound)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Only64";
    m_ctx.isNegated = true;

    m_isValidKey = [](const std::string&, RegistryView view)
    {
        return view == RegistryView::Bits64;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorTest, ValueOnlyIn64BitViewMatchesContent)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Only64";
    m_ctx.pattern = std::string("Val -> 0");

    m_isValidKey = [](const std::string&, RegistryView view)
    {
        return view == RegistryView::Bits64;
    };
    m_getValue = [](const std::string&, const std::string&, RegistryView view) -> std::optional<std::string>
    {
        if (view == RegistryView::Bits64)
        {
            return std::string("0");
        }

        return std::nullopt;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
    EXPECT_TRUE(evaluator.GetUnresolvedReason().empty());
}

TEST_F(RegistryRuleEvaluatorTest, ContentMatchingOnlyIn32BitViewReturnsFound)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Both";
    m_ctx.pattern = std::string("Val -> 0");

    m_getValue = [](const std::string&, const std::string&, RegistryView view) -> std::optional<std::string>
    {
        return std::string(view == RegistryView::Bits64 ? "1" : "0");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, ContentMatchingIn64BitViewSkips32BitView)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Both";
    m_ctx.pattern = std::string("Val -> 1");
    std::vector<RegistryView> queried;

    m_getValue = [&queried](const std::string&, const std::string&, RegistryView view) -> std::optional<std::string>
    {
        queried.push_back(view);
        return std::string(view == RegistryView::Bits64 ? "1" : "0");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
    EXPECT_EQ(queried, std::vector<RegistryView> {RegistryView::Bits64});
}

TEST_F(RegistryRuleEvaluatorTest, NegatedContentMatchingIn32BitViewReturnsNotFound)
{
    // Negation applies to the combined result: the rule must fail if any view matches,
    // even though the 64-bit view alone would make the negated rule pass.
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Both";
    m_ctx.pattern = std::string("Val -> 0");
    m_ctx.isNegated = true;

    m_getValue = [](const std::string&, const std::string&, RegistryView view) -> std::optional<std::string>
    {
        return std::string(view == RegistryView::Bits64 ? "1" : "0");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorTest, InvalidInOneViewAndNotFoundInOtherReturnsNotFound)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Only32";
    m_ctx.pattern = std::string("Val -> 0");

    m_isValidKey = [](const std::string&, RegistryView view)
    {
        return view == RegistryView::Bits32;
    };
    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::optional<std::string>
    {
        return std::string("1");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
    EXPECT_TRUE(evaluator.GetUnresolvedReason().empty());

    m_ctx.isNegated = true;
    auto negatedEvaluator = CreateEvaluator();
    EXPECT_EQ(negatedEvaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, InvalidInBothViewsReturnsInvalidEvenIfNegated)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Missing";
    m_ctx.pattern = std::string("Val -> 0");
    m_ctx.isNegated = true;

    m_isValidKey = [](const std::string&, RegistryView)
    {
        return false;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_EQ(evaluator.GetUnresolvedReason(), "Registry key 'HKLM\\SOFTWARE\\Microsoft\\Missing' does not exist");
}

TEST_F(RegistryRuleEvaluatorTest, InvalidInBothViewsKeepsFirstViewReason)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Restricted";
    m_ctx.pattern = std::string("Val -> 0");

    m_isValidKey = [](const std::string&, RegistryView view) -> bool
    {
        if (view == RegistryView::Bits64)
        {
            throw std::runtime_error("Access denied to registry key");
        }

        return false;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Access denied to registry key"));
}

TEST_F(RegistryRuleEvaluatorTest, ReasonFromPreviousEvaluationIsCleared)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Toggle";
    m_ctx.pattern = std::string("Val -> 0");
    auto exists = false;

    m_isValidKey = [&exists](const std::string&, RegistryView)
    {
        return exists;
    };
    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::optional<std::string>
    {
        return std::string("0");
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_FALSE(evaluator.GetUnresolvedReason().empty());

    exists = true;
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
    EXPECT_TRUE(evaluator.GetUnresolvedReason().empty());
}
