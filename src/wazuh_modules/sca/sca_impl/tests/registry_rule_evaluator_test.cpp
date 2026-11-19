#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

#include "logging_helper.hpp"

#include <windows.h>

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
            return {m_ctx, m_isValidKey, m_enumKeys, m_enumValues, m_getValue};
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

    m_enumKeys = [](const std::string&, RegistryView)
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

    m_enumKeys = [](const std::string&, RegistryView)
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

    m_enumKeys = [](const std::string&, RegistryView)
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

    m_enumKeys = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedKey"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorTest, PatternValueNameFoundReturnsFound)
{
    m_ctx.pattern = std::string("ExpectedValueName");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumKeys = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomeSubkey"};
    };
    m_enumValues = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedValueName"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, PatternRegexValueNameFoundReturnsFound)
{
    m_ctx.pattern = std::string("r:^Expected");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumValues = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomethingElse", "ExpectedValueName"};
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorTest, PatternNameInNeitherSubkeysNorValuesReturnsNotFound)
{
    m_ctx.pattern = std::string("MissingName");
    m_ctx.rule = "HKEY_CURRENT_USER\\MyApp";

    m_enumKeys = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomeSubkey"};
    };
    m_enumValues = [](const std::string&, RegistryView)
    {
        return std::vector<std::string> {"SomeValue"};
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

TEST_F(RegistryRuleEvaluatorTest, InvalidInBothViewsWithoutKeyKeepsFirstViewReason)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\Restricted";
    m_ctx.pattern = std::string("Val -> 0");

    // The injected lookup fails in the 64-bit view and finds no key in the 32-bit one
    m_isValidKey = [](const std::string&, RegistryView view) -> bool
    {
        if (view == RegistryView::Bits64)
        {
            throw std::runtime_error("Simulated registry lookup failure");
        }

        return false;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Simulated registry lookup failure"));
}

TEST_F(RegistryRuleEvaluatorTest, InvalidInBothViewsReportsReasonFromViewWhereKeyExists)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\OnlyIn32";
    m_ctx.pattern = std::string("Val -> 0");

    // The key exists only in the 32-bit view, and has no value 'Val'
    m_isValidKey = [](const std::string&, RegistryView view)
    {
        return view == RegistryView::Bits32;
    };
    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::optional<std::string>
    {
        return std::nullopt;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Registry value 'Val' does not exist"));
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::Not(::testing::HasSubstr("Registry key")));
}

TEST_F(RegistryRuleEvaluatorTest, InvalidInBothViewsKeepsFirstViewReasonWhenKeyExistsThere)
{
    m_ctx.rule = "HKLM\\SOFTWARE\\Microsoft\\OnlyIn64";
    m_ctx.pattern = std::string("Val -> 0");

    // The key exists only in the 64-bit view, and has no value 'Val'
    m_isValidKey = [](const std::string&, RegistryView view)
    {
        return view == RegistryView::Bits64;
    };
    m_getValue = [](const std::string&, const std::string&, RegistryView) -> std::optional<std::string>
    {
        return std::nullopt;
    };

    auto evaluator = CreateEvaluator();
    EXPECT_EQ(evaluator.Evaluate(), RuleResult::Invalid);
    EXPECT_THAT(evaluator.GetUnresolvedReason(), ::testing::HasSubstr("Registry value 'Val' does not exist"));
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

// Uses the evaluator's default registry functions against the real registry, so it fails if the
// lookups stop requesting a registry view explicitly. A 32-bit test process sees both views only
// under WOW64 (64-bit Windows, or Wine with a win64 prefix); elsewhere the tests are skipped.
class RegistryRuleEvaluatorRealRegistryTest : public ::testing::Test
{
    protected:
        std::string m_key64;
        std::string m_key32;

        static bool CreateKey(const std::string& subKey, const REGSAM view, HKEY& hKey)
        {
            return RegCreateKeyExA(HKEY_LOCAL_MACHINE,
                                   subKey.c_str(),
                                   0,
                                   nullptr,
                                   REG_OPTION_VOLATILE,
                                   KEY_ALL_ACCESS | view,
                                   nullptr,
                                   &hKey,
                                   nullptr) == ERROR_SUCCESS;
        }

        static bool KeyVisible(const std::string& subKey, const REGSAM view)
        {
            HKEY hKey = nullptr;
            const auto result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, subKey.c_str(), 0, KEY_READ | view, &hKey);

            if (hKey != nullptr)
            {
                RegCloseKey(hKey);
            }

            return result == ERROR_SUCCESS;
        }

        static void DeleteKey(const std::string& subKey, const REGSAM view)
        {
            RegDeleteKeyExA(HKEY_LOCAL_MACHINE, (subKey + "\\Child64").c_str(), view, 0);
            RegDeleteKeyExA(HKEY_LOCAL_MACHINE, subKey.c_str(), view, 0);
        }

        static RuleResult Evaluate(const std::string& rule, const std::optional<std::string>& pattern, const bool negated = false)
        {
            PolicyEvaluationContext ctx;
            ctx.rule = "HKEY_LOCAL_MACHINE\\" + rule;
            ctx.pattern = pattern;
            ctx.isNegated = negated;
            RegistryRuleEvaluator evaluator(ctx);
            return evaluator.Evaluate();
        }

        void SetUp() override
        {
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */) {});

            BOOL isWow64 = FALSE;

            if (!IsWow64Process(GetCurrentProcess(), &isWow64) || !isWow64)
            {
                GTEST_SKIP() << "The process does not run under WOW64, so there is a single registry view";
            }

            const auto suffix = std::to_string(GetCurrentProcessId());
            m_key64 = "SOFTWARE\\WazuhScaViewTest64_" + suffix;
            m_key32 = "SOFTWARE\\WazuhScaViewTest32_" + suffix;

            HKEY hKey64 = nullptr;
            HKEY hKey32 = nullptr;

            if (!CreateKey(m_key64, KEY_WOW64_64KEY, hKey64) || !CreateKey(m_key32, KEY_WOW64_32KEY, hKey32))
            {
                if (hKey64 != nullptr)
                {
                    RegCloseKey(hKey64);
                }

                GTEST_SKIP() << "Cannot create test keys under HKEY_LOCAL_MACHINE\\SOFTWARE (needs administrator rights)";
            }

            const DWORD one = 1;
            RegSetValueExA(hKey64, "Val", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&one), sizeof(one));

            HKEY hChild = nullptr;

            if (RegCreateKeyExA(hKey64, "Child64", 0, nullptr, REG_OPTION_VOLATILE, KEY_ALL_ACCESS | KEY_WOW64_64KEY, nullptr, &hChild, nullptr) ==
                    ERROR_SUCCESS)
            {
                RegCloseKey(hChild);
            }

            RegCloseKey(hKey64);
            RegCloseKey(hKey32);

            // The tests only mean something if each key is visible in its own view alone
            ASSERT_TRUE(KeyVisible(m_key64, KEY_WOW64_64KEY));
            ASSERT_FALSE(KeyVisible(m_key64, KEY_WOW64_32KEY));
            ASSERT_TRUE(KeyVisible(m_key32, KEY_WOW64_32KEY));
            ASSERT_FALSE(KeyVisible(m_key32, KEY_WOW64_64KEY));
        }

        void TearDown() override
        {
            if (!m_key64.empty())
            {
                DeleteKey(m_key64, KEY_WOW64_64KEY);
                DeleteKey(m_key32, KEY_WOW64_32KEY);
            }
        }
};

TEST_F(RegistryRuleEvaluatorRealRegistryTest, KeyOnlyIn64BitViewIsFound)
{
    EXPECT_EQ(Evaluate(m_key64, std::nullopt), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorRealRegistryTest, NegatedKeyOnlyIn64BitViewIsNotFound)
{
    EXPECT_EQ(Evaluate(m_key64, std::nullopt, true), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorRealRegistryTest, KeyOnlyIn32BitViewIsFound)
{
    EXPECT_EQ(Evaluate(m_key32, std::nullopt), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorRealRegistryTest, ValueOnlyIn64BitViewMatches)
{
    EXPECT_EQ(Evaluate(m_key64, std::string("Val -> 1")), RuleResult::Found);
    EXPECT_EQ(Evaluate(m_key64, std::string("Val -> 0")), RuleResult::NotFound);
}

TEST_F(RegistryRuleEvaluatorRealRegistryTest, SubkeyOnlyIn64BitViewIsFound)
{
    EXPECT_EQ(Evaluate(m_key64, std::string("r:^Child64$")), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorRealRegistryTest, ValueNameOnlyIn64BitViewIsFound)
{
    EXPECT_EQ(Evaluate(m_key64, std::string("Val")), RuleResult::Found);
}

TEST_F(RegistryRuleEvaluatorRealRegistryTest, KeyInNeitherViewIsNotFound)
{
    EXPECT_EQ(Evaluate(m_key64 + "_missing", std::nullopt), RuleResult::NotFound);
}
