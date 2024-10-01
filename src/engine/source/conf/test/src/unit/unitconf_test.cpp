#include <string>
#include <tuple>
#include <vector>

#include <gtest/gtest.h>

#include <conf/unitconf.hpp>

#include "utils.hpp"

using namespace conf::internal;

namespace
{

/************************************************************************
 *                              Build Test
 ************************************************************************/

struct UConfBuildTestParams
{
    std::string envName;
    std::variant<int, std::string, std::vector<std::string>, bool> defaultValue;
    bool expectThrow;

    UConfBuildTestParams(const std::string& env,
                         const std::variant<int, std::string, std::vector<std::string>, bool>& def,
                         bool expect = false)
        : envName(env)
        , defaultValue(def)
        , expectThrow(expect)
    {
    }
};

class UConfTest : public ::testing::TestWithParam<UConfBuildTestParams>
{
protected:
    void SetUp() override {}

    void TearDown() override {}
};

TEST_P(UConfTest, CreateUConf)
{
    auto& param = GetParam();
    try
    {
        auto confInt = std::shared_ptr<conf::internal::UConf<int>>();
        auto confStr = std::shared_ptr<conf::internal::UConf<std::string>>();
        auto confVec = std::shared_ptr<conf::internal::UConf<std::vector<std::string>>>();
        auto confBool = std::shared_ptr<conf::internal::UConf<bool>>();

        switch (param.defaultValue.index())
        {
            case 0: // int
                confInt = conf::internal::UConf<int>::make(param.envName, std::get<int>(param.defaultValue));
                EXPECT_EQ(confInt->getDefaultValue(), std::get<int>(param.defaultValue));
                EXPECT_EQ(confInt->getType(), UnitConfType::INTEGER);
                break;
            case 1: // std::string
                confStr =
                    conf::internal::UConf<std::string>::make(param.envName, std::get<std::string>(param.defaultValue));
                EXPECT_EQ(confStr->getDefaultValue(), std::get<std::string>(param.defaultValue));
                EXPECT_EQ(confStr->getType(), UnitConfType::STRING);
                break;
            case 2: // std::vector<std::string>
                confVec = conf::internal::UConf<std::vector<std::string>>::make(
                    param.envName, std::get<std::vector<std::string>>(param.defaultValue));
                EXPECT_EQ(confVec->getDefaultValue(), std::get<std::vector<std::string>>(param.defaultValue));
                EXPECT_EQ(confVec->getType(), UnitConfType::STRING_LIST);
                break;
            case 3: // bool
                confBool = conf::internal::UConf<bool>::make(param.envName, std::get<bool>(param.defaultValue));
                EXPECT_EQ(confBool->getDefaultValue(), std::get<bool>(param.defaultValue));
                EXPECT_EQ(confBool->getType(), UnitConfType::BOOL);
                break;
            default: FAIL() << "Unexpected index value: " << param.defaultValue.index(); break;
        }
        EXPECT_FALSE(param.expectThrow); // If we reach this point, the test is expected to pass
    }
    catch (const std::exception& e)
    {
        if (!param.expectThrow)
        {
            FAIL() << "Unexpected exception for param: " << param.envName << " with message: " << e.what();
        }
    }
}

// Check build and type for each type
INSTANTIATE_TEST_SUITE_P(UConfBuildValidTypes,
                         UConfTest,
                         ::testing::Values(
                             // int
                             UConfBuildTestParams("TEST_ENV_INT", 10),
                             UConfBuildTestParams("TEST_ENV_INT", -10),
                             UConfBuildTestParams("TEST_ENV_INT", 0),
                             UConfBuildTestParams("", -10, true),
                             // std::string
                             UConfBuildTestParams("TEST_ENV_STRING", std::string("hello")),
                             UConfBuildTestParams("TEST_ENV_STRING", std::string("")), // Can be empty
                             UConfBuildTestParams("TEST_ENV_STRING", std::string("hello world")),
                             UConfBuildTestParams("", std::string("hello"), true),
                             // std::vector<std::string>
                             UConfBuildTestParams("TEST_ENV_VECTOR", std::vector<std::string> {"hello", "world"}),
                             UConfBuildTestParams("TEST_ENV_VECTOR", std::vector<std::string> {"hello"}),
                             UConfBuildTestParams("TEST_ENV_VECTOR", std::vector<std::string> {}),
                             UConfBuildTestParams("", std::vector<std::string> {"hello", "world"}, true),
                             // bool
                             UConfBuildTestParams("TEST_ENV_BOOL", true),
                             UConfBuildTestParams("TEST_ENV_BOOL", false),
                             UConfBuildTestParams("", true, true),
                             UConfBuildTestParams("", false, true)));

TEST(UConfTest, CreateUConfTestTypes)
{

    auto testTypeFn = [](auto customType, bool shouldThrow)
    {
        try
        {
            auto conf = std::shared_ptr<conf::internal::UConf<decltype(customType)>>();
            conf = conf::internal::UConf<decltype(customType)>::make("TEST_ENV", customType);
            if (shouldThrow)
            {
                FAIL() << "Expected exception for custom type" << typeid(customType).name();
            }
        }
        catch (const std::invalid_argument& e)
        {
            if (!shouldThrow)
            {
                FAIL() << "Unexpected exception for custom type: " << e.what();
            }
        }
        catch (...)
        {
            FAIL() << "Unexpected exception for custom type";
        }
    };

    // Invalid types
    testTypeFn(1.0, true);
    testTypeFn(1.0f, true);
    testTypeFn(static_cast<float>(1.0), true);
    testTypeFn(static_cast<double>(1.0), true);
    testTypeFn('a', true);
    testTypeFn(nullptr, true);
    testTypeFn(std::vector<int> {1, 2, 3}, true);
    testTypeFn("hello", true); // char[]

    // Valid types
    testTypeFn(std::string("hello"), false);
    testTypeFn(static_cast<int>(1), false);
    testTypeFn(static_cast<int64_t>(1), false);
    testTypeFn(static_cast<int32_t>(1), false);
    testTypeFn(std::vector<std::string> {"hello", "world"}, false);
    testTypeFn(true, false);
    testTypeFn(false, false);
}

} // namespace

namespace
{

// Testing empty environment variable
TEST(UConfGetEnv, EmptyEnv)
{
    unsetEnv("TEST_EMPTY_ENV");
    auto conf = UConf<int>::make("TEST_EMPTY_ENV", 0);
    const auto envValue = conf->getEnvValue();
    EXPECT_FALSE(envValue.has_value());
}

// Testing int with params
// 1. Environment variable name
// 2. Environment variable value (string)
// 3. Expected value(Unused if expectThrow is true)
// 4. Expect exception
using IntTestParams = std::tuple<std::string, std::string, int64_t, bool>;

class IntTest : public ::testing::TestWithParam<IntTestParams>
{
protected:
    void SetUp() override
    {
        // Set the environment variable
        const auto& [env, value, expected, expectThrow] = GetParam();
        setEnv(env, value);
    }

    void TearDown() override { unsetEnv(std::get<0>(GetParam())); }
};

TEST_P(IntTest, GetEnvInt)
{
    const auto& [env, value, expected, expectThrow] = GetParam();

    auto conf = UConf<int>::make(env, 0);

    if (expectThrow)
    {
        EXPECT_THROW((conf->getEnvValue()), std::runtime_error);
    }
    else
    {
        const auto envValue = conf->getEnvValue();
        if (envValue.has_value())
        {
            EXPECT_EQ(envValue.value(), expected);
        }
        else
        {
            FAIL() << "Expected value for environment variable: " << env;
        }
    }
}

constexpr int IGNORE_INT_VALUE = 0;

INSTANTIATE_TEST_SUITE_P(
    UConfGetEnv,
    IntTest,
    ::testing::Values(
        IntTestParams("TEST_ENV_INT", "10", 10, false),
        IntTestParams("TEST_ENV_INT", "-10", -10, false),
        IntTestParams("TEST_ENV_INT", "0", 0, false),
        IntTestParams("TEST_ENV_INT", "10.0", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "10.0f", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "10.0", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "a", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "hello", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "true", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "false", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "1", 1, false),
        IntTestParams("TEST_ENV_INT", "0", 0, false),
        IntTestParams("TEST_ENV_INT", "-1", -1, false),
        IntTestParams(
            "TEST_ENV_INT", fmt::format("{}", std::numeric_limits<int>::min()), std::numeric_limits<int>::min(), false),
        IntTestParams(
            "TEST_ENV_INT", fmt::format("{}", std::numeric_limits<int>::max()), std::numeric_limits<int>::max(), false),
        IntTestParams(
            "TEST_ENV_INT", fmt::format("{}", static_cast<int64_t>(std::numeric_limits<int>::min()) - 1), 0, true),
        IntTestParams(
            "TEST_ENV_INT", fmt::format("{}", static_cast<int64_t>(std::numeric_limits<int>::max()) + 1), 0, true),
        IntTestParams("TEST_ENV_INT", "0x10", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "0b10", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "0o10", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", "10 ", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", " 10", IGNORE_INT_VALUE, true),
        IntTestParams("TEST_ENV_INT", " 10 ", IGNORE_INT_VALUE, true)));

// Testing int64_t with params
// 1. Environment variable name
// 2. Environment variable value (string)
// 3. Expected value(Unused if expectThrow is true)
// 4. Expect exception
using Int64TestParams = std::tuple<std::string, std::string, int64_t, bool>;

class Int64Test : public ::testing::TestWithParam<Int64TestParams>
{
protected:
    void SetUp() override
    {
        // Set the environment variable
        const auto& [env, value, expected, expectThrow] = GetParam();
        setEnv(env, value);
    }

    void TearDown() override { unsetEnv(std::get<0>(GetParam())); }
};

TEST_P(Int64Test, GetEnvInt64)
{
    const auto& [env, value, expected, expectThrow] = GetParam();

    auto conf = UConf<int64_t>::make(env, 0);

    if (expectThrow)
    {
        EXPECT_THROW((conf->getEnvValue()), std::runtime_error);
    }
    else
    {
        const auto envValue = conf->getEnvValue();
        if (envValue.has_value())
        {
            EXPECT_EQ(envValue.value(), expected);
        }
        else
        {
            FAIL() << "Expected value for environment variable: " << env;
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    UConfGetEnv,
    Int64Test,
    ::testing::Values(Int64TestParams("TEST_ENV_INT64", "10", 10, false),
                      Int64TestParams("TEST_ENV_INT64", "-10", -10, false),
                      Int64TestParams("TEST_ENV_INT64", "0", 0, false),
                      Int64TestParams("TEST_ENV_INT64", "10.0", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "10.0f", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "10.0", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "a", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "hello", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "true", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "false", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "1", 1, false),
                      Int64TestParams("TEST_ENV_INT64", "0", 0, false),
                      Int64TestParams("TEST_ENV_INT64", "-1", -1, false),
                      Int64TestParams("TEST_ENV_INT64",
                                      fmt::format("{}", std::numeric_limits<int64_t>::min()),
                                      std::numeric_limits<int64_t>::min(),
                                      false),
                      Int64TestParams("TEST_ENV_INT64",
                                      fmt::format("{}", std::numeric_limits<int64_t>::max()),
                                      std::numeric_limits<int64_t>::max(),
                                      false),
                      Int64TestParams("TEST_ENV_INT64",
                                      fmt::format("{}", static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 1),
                                      IGNORE_INT_VALUE,
                                      true),
                      Int64TestParams("TEST_ENV_INT64",
                                      fmt::format("-{}",
                                                  static_cast<uint64_t>(std::numeric_limits<int64_t>::max()) + 2),
                                      IGNORE_INT_VALUE,
                                      true),
                      Int64TestParams("TEST_ENV_INT64", "0x10", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "0b10", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "0o10", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", "10 ", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", " 10", IGNORE_INT_VALUE, true),
                      Int64TestParams("TEST_ENV_INT64", " 10 ", IGNORE_INT_VALUE, true)));

// Testing std::string with params
// 1. Environment variable name
// 2. Environment variable value (string)
// 3. Expected value

using StringTestParams = std::tuple<std::string, std::string, std::string>;

class StringTest : public ::testing::TestWithParam<StringTestParams>
{
protected:
    void SetUp() override
    {
        // Set the environment variable
        const auto& [env, value, expected] = GetParam();
        setEnv(env, value);
    }

    void TearDown() override { unsetEnv(std::get<0>(GetParam())); }
};

TEST_P(StringTest, GetEnvString)
{
    const auto& [env, value, expected] = GetParam();

    auto conf = UConf<std::string>::make(env, "");

    const auto envValue = conf->getEnvValue();
    if (envValue.has_value())
    {
        EXPECT_EQ(envValue.value(), expected);
    }
    else
    {
        FAIL() << "Expected value for environment variable: " << env;
    }
}

INSTANTIATE_TEST_SUITE_P(UConfGetEnv,
                         StringTest,
                         ::testing::Values(StringTestParams("TEST_ENV_STRING", "hello", "hello"),
                                           StringTestParams("TEST_ENV_STRING", "", ""),
                                           StringTestParams("TEST_ENV_STRING", "hello world", "hello world"),
                                           StringTestParams("TEST_ENV_STRING", "10", "10"),
                                           StringTestParams("TEST_ENV_STRING", "0", "0"),
                                           StringTestParams("TEST_ENV_STRING", "-1", "-1"),
                                           StringTestParams("TEST_ENV_STRING", "true", "true"),
                                           StringTestParams("TEST_ENV_STRING", "false", "false"),
                                           StringTestParams("TEST_ENV_STRING", "1", "1"),
                                           StringTestParams("TEST_ENV_STRING", "0x10", "0x10"),
                                           StringTestParams("TEST_ENV_STRING", "0b10", "0b10"),
                                           StringTestParams("TEST_ENV_STRING", "0o10", "0o10"),
                                           StringTestParams("TEST_ENV_STRING", "10 ", "10 "),
                                           StringTestParams("TEST_ENV_STRING", " 10", " 10"),
                                           StringTestParams("TEST_ENV_STRING", " 10 ", " 10 ")));

// Testing std::vector<std::string> with params
// 1. Environment variable name
// 2. Environment variable value (string)
// 3. Expected value
using StringListTestParams = std::tuple<std::string, std::string, std::vector<std::string>>;
class StringListTest : public ::testing::TestWithParam<StringListTestParams>
{
protected:
    void SetUp() override
    {
        // Set the environment variable
        const auto& [env, value, expected] = GetParam();
        setEnv(env, value);
    }

    void TearDown() override { unsetEnv(std::get<0>(GetParam())); }
};

TEST_P(StringListTest, GetEnvStringList)
{
    const auto& [env, value, expected] = GetParam();

    auto conf = UConf<std::vector<std::string>>::make(env, {});

    const auto envValue = conf->getEnvValue();
    if (envValue.has_value())
    {
        EXPECT_EQ(envValue.value(), expected);
    }
    else
    {
        FAIL() << "Expected value for environment variable: " << env;
    }
}

INSTANTIATE_TEST_SUITE_P(
    UConfGetEnv,
    StringListTest,
    ::testing::Values(
        StringListTestParams("TEST_ENV_STRING_LIST", "hello", std::vector<std::string> {"hello"}),
        StringListTestParams("TEST_ENV_STRING_LIST", "hello,world", std::vector<std::string> {"hello", "world"}),
        StringListTestParams("TEST_ENV_STRING_LIST", "", std::vector<std::string> {""}),
        StringListTestParams("TEST_ENV_STRING_LIST",
                             "hello,world,1,2,3",
                             std::vector<std::string> {"hello", "world", "1", "2", "3"}),
        StringListTestParams("TEST_ENV_STRING_LIST", R"(hello\,world)", std::vector<std::string> {"hello,world"}),
        StringListTestParams("TEST_ENV_STRING_LIST",
                             R"(hello\,world\,1\,2\,3)",
                             std::vector<std::string> {"hello,world,1,2,3"}),
        StringListTestParams("TEST_ENV_STRING_LIST",
                             R"(,hello, , , world, ,)",
                             std::vector<std::string> {"", "hello", " ", " ", " world", " ", ""}),
        StringListTestParams("TEST_ENV_STRING_LIST",
                             R"(,hello\, world, ,)",
                             std::vector<std::string> {"", "hello, world", " ", ""})));

// Testing bool with params
// 1. Environment variable name
// 2. Environment variable value (string)
// 3. Expected value (Unused if expectThrow is true)
// 4. Expect exception
using BoolTestParams = std::tuple<std::string, std::string, bool, bool>;

class BoolTest : public ::testing::TestWithParam<BoolTestParams>
{
protected:
    void SetUp() override
    {
        // Set the environment variable
        const auto& [env, value, expected, expectThrow] = GetParam();
        setEnv(env, value);
    }

    void TearDown() override { unsetEnv(std::get<0>(GetParam())); }
};

TEST_P(BoolTest, GetEnvBool)
{
    const auto& [env, value, expected, expectThrow] = GetParam();

    auto conf = UConf<bool>::make(env, false);

    if (expectThrow)
    {
        EXPECT_THROW((conf->getEnvValue()), std::runtime_error);
    }
    else
    {
        const auto envValue = conf->getEnvValue();
        if (envValue.has_value())
        {
            EXPECT_EQ(envValue.value(), expected);
        }
        else
        {
            FAIL() << "Expected value for environment variable: " << env;
        }
    }
}

constexpr bool IGNORE_EXPECTED = false;

INSTANTIATE_TEST_SUITE_P(UConfGetEnv,
                         BoolTest,
                         ::testing::Values(BoolTestParams("TEST_ENV_BOOL", "true", true, false),
                                           BoolTestParams("TEST_ENV_BOOL", "false", false, false),
                                           BoolTestParams("TEST_ENV_BOOL", "TRUE", true, false),
                                           BoolTestParams("TEST_ENV_BOOL", "FALSE", false, false),
                                           BoolTestParams("TEST_ENV_BOOL", "True", true, false),
                                           BoolTestParams("TEST_ENV_BOOL", "False", false, false),
                                           // Fail cases
                                           BoolTestParams("TEST_ENV_BOOL", "1", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "0", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "TRUE ", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", " FALSE", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", " TRUE ", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", " FALSE ", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "true ", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "false ", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", " true", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", " false", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", " true ", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", " false ", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "hello", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "hello world", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "10", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "0", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "-1", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "10.0", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "10.0f", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "10.0", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "a", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "1", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "0x10", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "0b10", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "0o10", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", "10 ", IGNORE_EXPECTED, true),
                                           BoolTestParams("TEST_ENV_BOOL", " 10", IGNORE_EXPECTED, true)));

} // namespace
