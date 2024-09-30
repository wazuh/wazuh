#include <gtest/gtest.h>

#include <conf/conf.hpp>

#include "utils.hpp"

namespace
{

/************************************************************************
 *                              Build Test
 ************************************************************************/
TEST(ConfTest, BuildConf)
{
    conf::Conf conf;
}

/************************************************************************
 *                       Load And Validate Test
 ************************************************************************/
/**
 * Test fixture for the Conf class.
 * the parameters are:
 * 1. JSON Returned from the API
 * 2. Expected failure
 */
class CustomConfValidate
    : public conf::Conf
    , public ::testing::TestWithParam<std::tuple<std::string, bool>>
{
protected:
    // Simulate the load from the API
    json::Json loadFromAPI() const
    {
        // auto super = conf::Conf::loadFromAPI();
        const auto& [jsonAPI, expectThrow] = GetParam();
        try
        {
            return json::Json(jsonAPI.c_str());
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error("Invalid JSON");
        }
    }

    void SetUp() override
    {

        // Add the configuration units
        addUnit("/TEST_INT", "TEST_ENV_INT", static_cast<int>(std::numeric_limits<int>::min()));
        addUnit("/TEST_INT64", "TEST_ENV_INT64", static_cast<int64_t>(std::numeric_limits<int64_t>::min()));
        addUnit("/TEST_STRING", "TEST_ENV_STRING", std::string("test"));
        addUnit("/TEST_STRING_LIST", "TEST_ENV_STRING_LIST", std::vector<std::string> {"hello", "world"});
        addUnit("/TEST_BOOL", "TEST_ENV_BOOL", false);

        // Add sub configuration
        addUnit("/SUB/TEST_INT", "TEST_ENV_INT", static_cast<int>(std::numeric_limits<int>::min()));
        addUnit("/SUB/TEST_INT64", "TEST_ENV_INT64", static_cast<int64_t>(std::numeric_limits<int64_t>::min()));
        addUnit("/SUB/TEST_STRING", "TEST_ENV_STRING", std::string("test"));
        addUnit("/SUB/TEST_STRING_LIST", "TEST_ENV_STRING_LIST", std::vector<std::string> {"hello", "world"});
        addUnit("/SUB/TEST_BOOL", "TEST_ENV_BOOL", false);
    }

    void TearDown() override {}
};

TEST_P(CustomConfValidate, LoadAndValidate)
{
    const auto& [jsonAPI, expectThrow] = GetParam();
    if (expectThrow)
    {
        EXPECT_THROW(load(), std::runtime_error);
    }
    else
    {
        EXPECT_NO_THROW(load());
    }
}

INSTANTIATE_TEST_SUITE_P(ConfLoadAndValidate,
                         CustomConfValidate,
                         ::testing::Values(
                             // Success
                             std::make_tuple("{}", false),
                             std::make_tuple(R"({"TEST_INT": 10})", false),
                             std::make_tuple(R"({"TEST_INT64": 10})", false),
                             std::make_tuple(R"({"TEST_STRING": "test"})", false),
                             std::make_tuple(R"({"TEST_STRING_LIST": ["hello", "world"]})", false),
                             std::make_tuple(R"({"TEST_BOOL": true})", false),
                             std::make_tuple(R"({"TEST_BOOL": false})", false),
                             // Success sub configuration
                             std::make_tuple(R"({"SUB": {"TEST_INT": 10}})", false),
                             std::make_tuple(R"({"SUB": {"TEST_INT64": 10}})", false),
                             std::make_tuple(R"({"SUB": {"TEST_STRING": "test"}})", false),
                             std::make_tuple(R"({"SUB": {"TEST_STRING_LIST": ["hello", "world"]}})", false),
                             std::make_tuple(R"({"SUB": {"TEST_BOOL": true}})", false),
                             // Failure
                             // Invalid int
                             std::make_tuple(R"({"TEST_INT": "invalid"})", true),
                             std::make_tuple(R"({"TEST_INT": "10.0"})", true),
                             std::make_tuple(R"({"TEST_INT": "9223372036854775808"})", true), // Out of range
                             std::make_tuple(R"({"TEST_INT": true})", true),
                             std::make_tuple(R"({"TEST_INT": ["10"]})", true),
                             std::make_tuple(R"({"TEST_INT": null})", true),
                             // Invalid int64
                             std::make_tuple(R"({"TEST_INT64": "invalid"})", true),
                             std::make_tuple(R"({"TEST_INT64": "10.0"})", true),
                             std::make_tuple(R"({"TEST_INT64": "9223372036854775808"})", true), // Out of range
                             std::make_tuple(R"({"TEST_INT64": true})", true),
                             std::make_tuple(R"({"TEST_INT64": ["10"]})", true),
                             std::make_tuple(R"({"TEST_INT64": null})", true),
                             // Invalid string
                             std::make_tuple(R"({"TEST_STRING": 10})", true),
                             std::make_tuple(R"({"TEST_STRING": ["test"]})", true),
                             std::make_tuple(R"({"TEST_STRING": null})", true),
                             // Invalid string list
                             std::make_tuple(R"({"TEST_STRING_LIST": "hello"})", true),
                             std::make_tuple(R"({"TEST_STRING_LIST": ["hello", 10]})", true),
                             std::make_tuple(R"({"TEST_STRING_LIST": null})", true),
                             std::make_tuple(R"({"TEST_STRING_LIST": "hello,world"})", true),
                             std::make_tuple(R"({"TEST_STRING_LIST": 123})", true),
                             // Invalid bool
                             std::make_tuple(R"({"TEST_BOOL": "invalid"})", true),
                             std::make_tuple(R"({"TEST_BOOL": 10})", true),
                             std::make_tuple(R"({"TEST_BOOL": ["true"]})", true),
                             std::make_tuple(R"({"TEST_BOOL": null})", true),
                             // Invalid sub configuration
                             // Invalid int
                             std::make_tuple(R"({"SUB": {"TEST_INT": "invalid"}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_INT": "10.0"}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_INT": "9223372036854775808"}})", true), // Out of range
                             std::make_tuple(R"({"SUB": {"TEST_INT": true}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_INT": ["10"]}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_INT": null}})", true),
                             // Invalid int64
                             std::make_tuple(R"({"SUB": {"TEST_INT64": "invalid"}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_INT64": "10.0"}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_INT64": "9223372036854775808"}})", true), // Out of range
                             std::make_tuple(R"({"SUB": {"TEST_INT64": true}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_INT64": ["10"]}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_INT64": null}})", true),
                             // Invalid string
                             std::make_tuple(R"({"SUB": {"TEST_STRING": 10}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_STRING": ["test"]}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_STRING": null}})", true),
                             // Invalid string list
                             std::make_tuple(R"({"SUB": {"TEST_STRING_LIST": "hello"}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_STRING_LIST": ["hello", 10]})", true),
                             std::make_tuple(R"({"SUB": {"TEST_STRING_LIST": null}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_STRING_LIST": "hello,world"})", true),
                             // Invalid bool
                             std::make_tuple(R"({"SUB": {"TEST_BOOL": "invalid"}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_BOOL": 10}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_BOOL": ["true"]}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_BOOL": null}})", true)));

/************************************************************************
 *                       Priority Test
 ************************************************************************/
// TODO

} // namespace
