#include <string>
#include <tuple>
#include <vector>

#include <gtest/gtest.h>

#include <conf/unitconf.hpp>

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


namespace {

/************************************************************************
 *                              test getEnv
 ************************************************************************/
void setEnv(const std::string& env, const std::string& value)
{
    setenv(env.c_str(), value.c_str(), 1);

    // Check if the environment variable was set correctly
    const auto pValue = std::getenv(env.c_str());
    if (pValue == nullptr)
    {
        FAIL() << "Failed to set environment variable: " << env;
    }
    const auto envValue = std::string(pValue);
    EXPECT_EQ(envValue, value);

}

void unsetEnv(const std::string& env)
{
    unsetenv(env.c_str());

    // Check if the environment variable was unset correctly
    const auto pValue = std::getenv(env.c_str());
    if (pValue != nullptr)
    {
        FAIL() << "Failed to unset environment variable: " << env;
    }
}

} // namespace


