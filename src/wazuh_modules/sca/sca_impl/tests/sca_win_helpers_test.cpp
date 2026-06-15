#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <sca_policy_check.hpp>

#include "logging_helper.hpp"

#include <windows.h>

#include <optional>
#include <stdexcept>
#include <string>

namespace
{
    // RAII guard that sets a process environment variable and restores its
    // prior value (or absence) on destruction.
    class ScopedEnvVar
    {
        public:
            ScopedEnvVar(const char* name, const char* value)
                : m_name(name)
            {
                if (const auto size = ::GetEnvironmentVariableA(m_name, nullptr, 0); size > 0)
                {
                    std::string prior(size, '\0');
                    const auto read = ::GetEnvironmentVariableA(m_name, prior.data(), size);

                    if (read > 0 && read < size)
                    {
                        prior.resize(read);
                        m_prior = std::move(prior);
                    }
                }

                if (!::SetEnvironmentVariableA(m_name, value))
                {
                    throw std::runtime_error("SetEnvironmentVariableA failed");
                }
            }

            ~ScopedEnvVar()
            {
                ::SetEnvironmentVariableA(m_name, m_prior ? m_prior->c_str() : nullptr);
            }

            ScopedEnvVar(const ScopedEnvVar&) = delete;
            ScopedEnvVar& operator=(const ScopedEnvVar&) = delete;
            ScopedEnvVar(ScopedEnvVar&&) = delete;
            ScopedEnvVar& operator=(ScopedEnvVar&&) = delete;

        private:
            const char* m_name;
            std::optional<std::string> m_prior;
    };

    template<typename T>
    bool IsInstanceOf(const IRuleEvaluator* evaluator)
    {
        return dynamic_cast<const T*>(evaluator) != nullptr;
    }
}

class SCAWinHelpersTest : public ::testing::Test
{
    protected:
        void SetUp() override
        {
            LoggingHelper::setLogCallback([](const modules_log_level_t /* level */, const char* /* log */)
            {
            });
        }
};

// -----------------------------------------------------------------------------
// Unit tests of sca::win::ExpandEnvironmentVariables
// -----------------------------------------------------------------------------

TEST_F(SCAWinHelpersTest, ExpandsKnownEnvironmentVariable)
{
    const ScopedEnvVar envVar("SCA_TEST_ROOT", "C:\\Windows");

    EXPECT_EQ(sca::win::ExpandEnvironmentVariables("%SCA_TEST_ROOT%\\win.ini"),
              "C:\\Windows\\win.ini");
}

TEST_F(SCAWinHelpersTest, LeavesUnknownEnvVarLiteral)
{
    // ExpandEnvironmentStringsA leaves unknown "%...%" tokens as literal text.
    constexpr const char* kUnsetVar = "SCA_TEST_DEFINITELY_UNSET";
    ASSERT_EQ(::GetEnvironmentVariableA(kUnsetVar, nullptr, 0), 0u);

    const std::string input = "C:\\Apps\\%" + std::string(kUnsetVar) + "%\\app.cfg";

    EXPECT_EQ(sca::win::ExpandEnvironmentVariables(input), input);
}

TEST_F(SCAWinHelpersTest, ReturnsInputUnchangedWhenNoTokensPresent)
{
    EXPECT_EQ(sca::win::ExpandEnvironmentVariables("C:\\Windows\\notepad.exe"),
              "C:\\Windows\\notepad.exe");
}

TEST_F(SCAWinHelpersTest, ReturnsEmptyForEmptyInput)
{
    EXPECT_EQ(sca::win::ExpandEnvironmentVariables(""), "");
}

TEST_F(SCAWinHelpersTest, ExpandsMultipleVariablesInSingleInput)
{
    const ScopedEnvVar drive("SCA_TEST_DRIVE", "C:");
    const ScopedEnvVar leaf("SCA_TEST_LEAF", "config.ini");

    EXPECT_EQ(sca::win::ExpandEnvironmentVariables("%SCA_TEST_DRIVE%\\apps\\%SCA_TEST_LEAF%"),
              "C:\\apps\\config.ini");
}

// -----------------------------------------------------------------------------
// Integration test through RuleEvaluatorFactory
// -----------------------------------------------------------------------------

TEST_F(SCAWinHelpersTest, FactoryExpandsEnvironmentVariablesInRuleInput)
{
    const ScopedEnvVar envVar("SCA_TEST_ROOT", "C:\\Windows");

    auto evaluator = RuleEvaluatorFactory::CreateEvaluator(
                         "f:%SCA_TEST_ROOT%\\win.ini -> enabled", 30, false);

    ASSERT_NE(evaluator, nullptr);
    ASSERT_TRUE(IsInstanceOf<FileRuleEvaluator>(evaluator.get()));

    const auto* base = dynamic_cast<const RuleEvaluator*>(evaluator.get());
    ASSERT_NE(base, nullptr);

    const auto& ctx = base->GetContext();
    EXPECT_EQ(ctx.rule, "C:\\Windows\\win.ini");
    ASSERT_TRUE(ctx.pattern.has_value());
    EXPECT_EQ(ctx.pattern.value(), "enabled");
}
