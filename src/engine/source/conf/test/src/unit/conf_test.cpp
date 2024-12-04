#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <conf/conf.hpp>

#include "mockApiLoader.hpp"
#include "utils.hpp"

namespace conf::mocks
{
std::shared_ptr<MockApiLoader> createMockApiLoader(const std::string& json)
{
    auto mockApiLoader = std::make_shared<MockApiLoader>();

    try
    {
        auto jConf = json::Json(json.c_str());
        EXPECT_CALL(*mockApiLoader, load()).WillOnce(testing::Return(jConf));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Error creating the mock API loader: '{}' | json: '{}'", e.what(), json));
    }
    return mockApiLoader;
}
} // namespace conf::mocks
namespace
{

/************************************************************************
 *                              Build Test
 ************************************************************************/
TEST(ConfTest, BuildConf)
{
    // Success
    conf::Conf conf(std::make_shared<conf::mocks::MockApiLoader>());

    // Failure
    EXPECT_THROW(conf::Conf(nullptr), std::invalid_argument);
}

/************************************************************************
 *                       Add Unit Test
 ************************************************************************/

TEST(AddUnit, success)
{
    conf::Conf conf(std::make_shared<conf::mocks::MockApiLoader>());

    // Success
    EXPECT_NO_THROW(conf.addUnit("/TEST", "TEST_ENV", 10));
    EXPECT_NO_THROW(conf.addUnit("/TEST_1", "TEST_ENV_1", static_cast<int64_t>(std::numeric_limits<int64_t>::min())));
    EXPECT_NO_THROW(conf.addUnit("/TEST_2", "TEST_ENV_2", std::string("test")));
    EXPECT_NO_THROW(conf.addUnit("/TEST_3", "TEST_ENV_3", std::vector<std::string> {"hello", "world"}));
    EXPECT_NO_THROW(conf.addUnit("/TEST_4", "TEST_ENV_4", false));
}

TEST(AddUnit, duplicateOrEmpty)
{
    conf::Conf conf(std::make_shared<conf::mocks::MockApiLoader>());

    // Failure, duplicate
    EXPECT_NO_THROW(conf.addUnit("/TEST_DUPLICATE", "TEST_ENV_DUPLICATE", 10));
    EXPECT_THROW(conf.addUnit("/TEST_DUPLICATE", "TEST_ENV_DUPLICATE", 10), std::invalid_argument);

    // Same Key
    EXPECT_NO_THROW(conf.addUnit("/TEST_SAME_KEY", "TEST_SAME_KEY_0", 10));
    EXPECT_THROW(conf.addUnit("/TEST_SAME_KEY", "TEST_SAME_KEY_1", 10), std::invalid_argument);

    // Same Environment variable
    EXPECT_NO_THROW(conf.addUnit("/TEST_SAME_ENV_0", "TEST_SAME_ENV", 10));
    EXPECT_THROW(conf.addUnit("/TEST_SAME_ENV_1", "TEST_SAME_ENV", 10), std::invalid_argument);

    // Empty key
    EXPECT_THROW(conf.addUnit("", "TEST_EMPTY", 10), std::invalid_argument);

    // Empty environment variable
    EXPECT_THROW(conf.addUnit("/TEST_EMPTY", "", 10), std::invalid_argument);

    // Empty key and environment variable
    EXPECT_THROW(conf.addUnit("", "", 10), std::invalid_argument);
}

TEST(AddUnit, addBeforeLoad)
{
    auto mockApiLoader = conf::mocks::createMockApiLoader("{}");
    conf::Conf conf(mockApiLoader);

    // Success
    EXPECT_NO_THROW(conf.addUnit("/TEST", "TEST_ENV", 10));

    // Load
    EXPECT_NO_THROW(conf.load());

    // Failure, add after load
    EXPECT_THROW(conf.addUnit("/TEST_1", "TEST_ENV_1", 10), std::logic_error);
}

/************************************************************************
 *                       Load And Validate Test
 ************************************************************************/
TEST(LoadTest, Multiload)
{
    auto mockApiLoader = conf::mocks::createMockApiLoader("{}");
    conf::Conf conf(mockApiLoader);

    // Success
    EXPECT_NO_THROW(conf.load());
    EXPECT_THROW(conf.load(), std::logic_error);
}

/**
 * Test fixture for the Conf class.
 * the parameters are:
 * 1. JSON Returned from the API
 * 2. Expected failure
 */
class CustomConfValidate : public ::testing::TestWithParam<std::tuple<std::string, bool>>
{
protected:
    std::shared_ptr<conf::mocks::MockApiLoader> m_apiLoader;
    std::shared_ptr<conf::Conf> m_conf;

    void SetUp() override
    {
        auto m_apiLoader = conf::mocks::createMockApiLoader(std::get<0>(GetParam()));
        m_conf = std::make_shared<conf::Conf>(m_apiLoader);

        // Add the configuration units
        m_conf->addUnit("/TEST_INT", "TEST_ENV_INT", static_cast<int>(std::numeric_limits<int>::min()));
        m_conf->addUnit("/TEST_INT64", "TEST_ENV_INT64", static_cast<int64_t>(std::numeric_limits<int64_t>::min()));
        m_conf->addUnit("/TEST_STRING", "TEST_ENV_STRING", std::string("test"));
        m_conf->addUnit("/TEST_STRING_LIST", "TEST_ENV_STRING_LIST", std::vector<std::string> {"hello", "world"});
        m_conf->addUnit("/TEST_BOOL", "TEST_ENV_BOOL", false);

        // Add sub configuration
        m_conf->addUnit("/SUB/TEST_INT", "SUB_TEST_ENV_INT", static_cast<int>(std::numeric_limits<int>::min()));
        m_conf->addUnit(
            "/SUB/TEST_INT64", "SUB_TEST_ENV_INT64", static_cast<int64_t>(std::numeric_limits<int64_t>::min()));
        m_conf->addUnit("/SUB/TEST_STRING", "SUB_TEST_ENV_STRING", std::string("test"));
        m_conf->addUnit(
            "/SUB/TEST_STRING_LIST", "SUB_TEST_ENV_STRING_LIST", std::vector<std::string> {"hello", "world"});
        m_conf->addUnit("/SUB/TEST_BOOL", "SUB_TEST_ENV_BOOL", false);
    }

    void TearDown() override
    {
        // check pending expectations
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(m_apiLoader.get()));

        m_conf.reset();
        m_apiLoader.reset();
    }
};

TEST_P(CustomConfValidate, LoadAndValidate)
{
    const auto& expectThrow = std::get<1>(GetParam());
    if (expectThrow)
    {
        EXPECT_THROW(m_conf->load(), std::runtime_error);
    }
    else
    {
        EXPECT_NO_THROW(m_conf->load());
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
                             std::make_tuple(R"({"SUB": {"TEST_STRING_LIST": ["hello", 10]}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_STRING_LIST": null}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_STRING_LIST": "hello,world"}})", true),
                             // Invalid bool
                             std::make_tuple(R"({"SUB": {"TEST_BOOL": "invalid"}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_BOOL": 10}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_BOOL": ["true"]}})", true),
                             std::make_tuple(R"({"SUB": {"TEST_BOOL": null}})", true)));

/************************************************************************
 *                       Priority Test
 ************************************************************************/
/**
 * Test fixture for the Conf class, testing the priority order, no validation of the API.
 * the parameters are:
 * 1. Default value
 * 2. JSON Returned from the API
 * 3. Optional environment variable value
 * 4. Expected value from the configuration
 * 5. Expected failure
 */

enum class ExpFailType
{
    ON_API_LOAD, ///< Expected failure on load (Data validation)
    ON_GET,      ///< Expected failure on get (Data validation)
    NONE         ///< No expected failure
};

template<typename T>
class CustomConfPriorityTypeT
    : public ::testing::TestWithParam<std::tuple<T, std::string, std::optional<std::string>, T, ExpFailType>>
{
protected:
    std::shared_ptr<conf::IApiLoader> m_apiLoader;
    std::shared_ptr<conf::Conf> m_conf;

    void SetUp() override
    {
        logging::testInit();

        const auto& json = std::get<1>(this->GetParam());
        m_apiLoader = conf::mocks::createMockApiLoader(json);
        m_conf = std::make_shared<conf::Conf>(m_apiLoader);

        // Add the configuration units
        m_conf->addUnit("/TEST", "TEST_ENV", std::get<0>(this->GetParam()));

        // Set the environment variable
        if (std::get<2>(this->GetParam()))
        {
            setEnv("TEST_ENV", *std::get<2>(this->GetParam()));
        }

        // Load the configuration
        if (std::get<4>(this->GetParam()) == ExpFailType::ON_API_LOAD)
        {
            EXPECT_THROW(m_conf->load(), std::runtime_error);
            // End the test
            SUCCEED();
        }
        else
        {
            m_conf->load();
        }
    }

    void TearDown() override
    {
        // check pending expectations
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(m_apiLoader.get()));

        // Unset the environment variable
        unsetEnv("TEST_ENV");

        m_conf.reset();
        m_apiLoader.reset();
    }

    void runTest()
    {
        const auto& expectException = std::get<4>(this->GetParam());

        switch (expectException)
        {
            case ExpFailType::ON_API_LOAD: return;
            case ExpFailType::ON_GET: EXPECT_THROW(m_conf->get<T>("/TEST"), std::runtime_error); break;
            case ExpFailType::NONE: EXPECT_EQ(m_conf->get<T>("/TEST"), std::get<3>(this->GetParam())); break;
            default: FAIL() << "Unexpected expected failure";
        }
    }
};

using CustomConfPriorityInt = CustomConfPriorityTypeT<int>;
TEST_P(CustomConfPriorityInt, PriorityInt)
{
    runTest();
}

INSTANTIATE_TEST_SUITE_P(ConfPriorityInt,
                         CustomConfPriorityInt,
                         ::testing::Values(
                             // Default value | JSON API | Environment variable | Expected value | Expected failure
                             // Success
                             std::make_tuple(10, "{}", std::nullopt, 10, ExpFailType::NONE),
                             std::make_tuple(10, "{}", "20", 20, ExpFailType::NONE),
                             std::make_tuple(10, R"({"TEST": 20})", std::nullopt, 20, ExpFailType::NONE),
                             std::make_tuple(10, R"({"TEST": 20})", "30", 30, ExpFailType::NONE),
                             // Failure on get the value
                             std::make_tuple(10, "{}", "invalid", 10, ExpFailType::ON_GET),
                             std::make_tuple(10, R"({"TEST": 20})", "invalid", 20, ExpFailType::ON_GET),
                             // Failure on load the configuration (Data validation)
                             std::make_tuple(10, R"({"TEST": "invalid"})", std::nullopt, 10, ExpFailType::ON_API_LOAD),
                             std::make_tuple(10, R"({"TEST": false})", std::nullopt, 10, ExpFailType::ON_API_LOAD),
                             std::make_tuple(10, R"({"TEST": null})", std::nullopt, 10, ExpFailType::ON_API_LOAD)
                             // END
                             ));

using CustomConfPriorityInt64 = CustomConfPriorityTypeT<int64_t>;
TEST_P(CustomConfPriorityInt64, PriorityInt64)
{
    runTest();
}

INSTANTIATE_TEST_SUITE_P(ConfPriorityInt64,
                         CustomConfPriorityInt64,
                         ::testing::Values(
                             // Default value | JSON API | Environment variable | Expected value | Expected failure
                             // Success
                             std::make_tuple(10, "{}", std::nullopt, 10, ExpFailType::NONE),
                             std::make_tuple(10, "{}", "20", 20, ExpFailType::NONE),
                             std::make_tuple(10, R"({"TEST": 20})", std::nullopt, 20, ExpFailType::NONE),
                             std::make_tuple(10, R"({"TEST": 20})", "30", 30, ExpFailType::NONE),
                             std::make_tuple(std::numeric_limits<int64_t>::min(),
                                             "{}",
                                             std::nullopt,
                                             std::numeric_limits<int64_t>::min(),
                                             ExpFailType::NONE),
                             std::make_tuple(std::numeric_limits<int64_t>::min(),
                                             R"({"TEST": 9223372036854775807})",
                                             std::nullopt,
                                             9223372036854775807,
                                             ExpFailType::NONE),
                             // Failure on get the value
                             std::make_tuple(10, "{}", "invalid", 10, ExpFailType::ON_GET),
                             std::make_tuple(10, R"({"TEST": 20})", "invalid", 20, ExpFailType::ON_GET),
                             // Failure on load the configuration (Data validation)
                             std::make_tuple(10, R"({"TEST": "invalid"})", std::nullopt, 10, ExpFailType::ON_API_LOAD),
                             std::make_tuple(10, R"({"TEST": false})", std::nullopt, 10, ExpFailType::ON_API_LOAD),
                             std::make_tuple(10, R"({"TEST": null})", std::nullopt, 10, ExpFailType::ON_API_LOAD)
                             // END
                             ));

using CustomConfPriorityString = CustomConfPriorityTypeT<std::string>;
TEST_P(CustomConfPriorityString, PriorityString)
{
    runTest();
}

INSTANTIATE_TEST_SUITE_P(
    ConfPriorityString,
    CustomConfPriorityString,
    ::testing::Values(
        // Default value | JSON API | Environment variable | Expected value | Expected failure
        // Success
        std::make_tuple("test", "{}", std::nullopt, "test", ExpFailType::NONE),
        std::make_tuple("test", "{}", "hello", "hello", ExpFailType::NONE),
        std::make_tuple("test", R"({"TEST": "hello"})", std::nullopt, "hello", ExpFailType::NONE),
        std::make_tuple("test", R"({"TEST": "hello"})", "world", "world", ExpFailType::NONE),
        std::make_tuple("test", "{}", "10", "10", ExpFailType::NONE),
        // Cannot fail on get the value if the type is string, only in the API load
        // Failure on load the configuration (Data validation)
        std::make_tuple("test", R"({"TEST": 10})", std::nullopt, "test", ExpFailType::ON_API_LOAD),
        std::make_tuple("test", R"({"TEST": false})", std::nullopt, "test", ExpFailType::ON_API_LOAD),
        std::make_tuple("test", R"({"TEST": null})", std::nullopt, "test", ExpFailType::ON_API_LOAD)
        // END
        ));

using CustomConfPriorityStringList = CustomConfPriorityTypeT<std::vector<std::string>>;

TEST_P(CustomConfPriorityStringList, PriorityStringList)
{
    runTest();
}

INSTANTIATE_TEST_SUITE_P(ConfPriorityStringList,
                         CustomConfPriorityStringList,
                         ::testing::Values(
                             // Default value | JSON API | Environment variable | Expected value | Expected failure
                             // Success
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             "{}",
                                             std::nullopt,
                                             std::vector<std::string> {"hello", "world"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             "{}",
                                             "hello,world",
                                             std::vector<std::string> {"hello", "world"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             R"({"TEST": ["hello", "world"]})",
                                             std::nullopt,
                                             std::vector<std::string> {"hello", "world"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             R"({"TEST": ["hello", "world"]})",
                                             "world,hello",
                                             std::vector<std::string> {"world", "hello"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             "{}",
                                             "hello",
                                             std::vector<std::string> {"hello"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             "{}",
                                             "hello,10",
                                             std::vector<std::string> {"hello", "10"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             "{}",
                                             R"(hello\,world)",
                                             std::vector<std::string> {"hello,world"},
                                             ExpFailType::NONE),
                             // Cannot fail on get the value if the type is string, only in the API load
                             // Failure on load the configuration (Data validation)
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             R"({"TEST": "hello"})",
                                             std::nullopt,
                                             std::vector<std::string> {"hello", "world"},
                                             ExpFailType::ON_API_LOAD),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             R"({"TEST": ["hello", 10]})",
                                             std::nullopt,
                                             std::vector<std::string> {"hello", "world"},
                                             ExpFailType::ON_API_LOAD),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             R"({"TEST": null})",
                                             std::nullopt,
                                             std::vector<std::string> {"hello", "world"},
                                             ExpFailType::ON_API_LOAD)
                             // END
                             ));

using CustomConfPriorityBool = CustomConfPriorityTypeT<bool>;

TEST_P(CustomConfPriorityBool, PriorityBool)
{
    runTest();
}

INSTANTIATE_TEST_SUITE_P(
    ConfPriorityBool,
    CustomConfPriorityBool,
    ::testing::Values(
        // Default value | JSON API | Environment variable | Expected value | Expected failure
        // Success
        std::make_tuple(false, "{}", std::nullopt, false, ExpFailType::NONE),
        std::make_tuple(false, "{}", "true", true, ExpFailType::NONE),
        std::make_tuple(false, R"({"TEST": true})", std::nullopt, true, ExpFailType::NONE),
        std::make_tuple(false, R"({"TEST": true})", "false", false, ExpFailType::NONE),
        std::make_tuple(true, R"({"TEST": true})", "false", false, ExpFailType::NONE),
        // Failure on get the value
        std::make_tuple(false, "{}", "invalid", false, ExpFailType::ON_GET),
        std::make_tuple(false, R"({"TEST": true})", "invalid", true, ExpFailType::ON_GET),
        // Failure on load the configuration (Data validation)
        std::make_tuple(false, R"({"TEST": "invalid"})", std::nullopt, false, ExpFailType::ON_API_LOAD),
        std::make_tuple(false, R"({"TEST": 10})", std::nullopt, false, ExpFailType::ON_API_LOAD),
        std::make_tuple(false, R"({"TEST": null})", std::nullopt, false, ExpFailType::ON_API_LOAD)
        // END
        ));

TEST(ConfGet, invalidType)
{
    // Bad type, should throw a logic error, add INT get DOUBLE
    conf::Conf conf(std::make_shared<conf::mocks::MockApiLoader>());
    conf.addUnit("/TEST", "TEST_ENV", 10);
    EXPECT_THROW(conf.get<double>("/TEST"), std::logic_error);
}

TEST(ConfGet, badKey)
{

    conf::Conf conf(std::make_shared<conf::mocks::MockApiLoader>());

    EXPECT_THROW(conf.get<int>("/TEST"), std::runtime_error);
}
} // namespace
