#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <conf/conf.hpp>

#include "mockFileLoader.hpp"
#include "utils.hpp"

namespace conf::mocks
{
std::shared_ptr<MockFileLoader> createMockFileLoader(const OptionMap& configMap)
{
    auto mockFileLoader = std::make_shared<MockFileLoader>();

    try
    {
        EXPECT_CALL(*mockFileLoader, load()).WillOnce(testing::Return(configMap));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Error creating the mock file loader: '{}'", e.what()));
    }
    return mockFileLoader;
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
    conf::Conf conf(std::make_shared<conf::mocks::MockFileLoader>());

    // Failure
    EXPECT_THROW(conf::Conf(nullptr), std::invalid_argument);
}

/************************************************************************
 *                       Add Unit Test
 ************************************************************************/

TEST(AddUnit, success)
{
    conf::Conf conf(std::make_shared<conf::mocks::MockFileLoader>());

    // Success
    EXPECT_NO_THROW(conf.addUnit("TEST", "TEST_ENV", 10));
    EXPECT_NO_THROW(conf.addUnit("TEST_1", "TEST_ENV_1", static_cast<int64_t>(std::numeric_limits<int64_t>::min())));
    EXPECT_NO_THROW(conf.addUnit("TEST_2", "TEST_ENV_2", std::string("test")));
    EXPECT_NO_THROW(conf.addUnit("TEST_3", "TEST_ENV_3", std::vector<std::string> {"hello", "world"}));
    EXPECT_NO_THROW(conf.addUnit("TEST_4", "TEST_ENV_4", false));
}

TEST(AddUnit, duplicateOrEmpty)
{
    conf::Conf conf(std::make_shared<conf::mocks::MockFileLoader>());

    // Failure, duplicate
    EXPECT_NO_THROW(conf.addUnit("TEST_DUPLICATE", "TEST_ENV_DUPLICATE", 10));
    EXPECT_THROW(conf.addUnit("TEST_DUPLICATE", "TEST_ENV_DUPLICATE", 10), std::invalid_argument);

    // Same Key
    EXPECT_NO_THROW(conf.addUnit("TEST_SAME_KEY", "TEST_SAME_KEY_0", 10));
    EXPECT_THROW(conf.addUnit("TEST_SAME_KEY", "TEST_SAME_KEY_1", 10), std::invalid_argument);

    // Same Environment variable
    EXPECT_NO_THROW(conf.addUnit("TEST_SAME_ENV_0", "TEST_SAME_ENV", 10));
    EXPECT_THROW(conf.addUnit("TEST_SAME_ENV_1", "TEST_SAME_ENV", 10), std::invalid_argument);

    // Empty key
    EXPECT_THROW(conf.addUnit("", "TEST_EMPTY", 10), std::invalid_argument);

    // Empty environment variable
    EXPECT_THROW(conf.addUnit("TEST_EMPTY", "", 10), std::invalid_argument);

    // Empty key and environment variable
    EXPECT_THROW(conf.addUnit("", "", 10), std::invalid_argument);
}

TEST(AddUnit, addBeforeLoad)
{
    conf::OptionMap configMap;
    configMap["analysisd.example"] = "true";
    auto mockFileLoader = conf::mocks::createMockFileLoader(configMap);
    conf::Conf conf(mockFileLoader);

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
    conf::OptionMap configMap;
    configMap["analysisd.example"] = "true";
    auto mockFileLoader = conf::mocks::createMockFileLoader(configMap);
    conf::Conf conf(mockFileLoader);

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
class CustomConfValidate : public ::testing::TestWithParam<std::tuple<conf::OptionMap, bool>>
{
protected:
    std::shared_ptr<conf::mocks::MockFileLoader> m_fileLoader;
    std::shared_ptr<conf::Conf> m_conf;

    void SetUp() override
    {
        auto m_fileLoader = conf::mocks::createMockFileLoader(std::get<0>(GetParam()));
        m_conf = std::make_shared<conf::Conf>(m_fileLoader);

        // Add the configuration units
        m_conf->addUnit("TEST.INT", "TEST_ENV_INT", static_cast<int>(std::numeric_limits<int>::min()));
        m_conf->addUnit("TEST.INT64", "TEST_ENV_INT64", static_cast<int64_t>(std::numeric_limits<int64_t>::min()));
        m_conf->addUnit("TEST.STRING", "TEST_ENV_STRING", std::string("test"));
        m_conf->addUnit("TEST.STRING_LIST", "TEST_ENV_STRING_LIST", std::vector<std::string> {"hello", "world"});
        m_conf->addUnit("TEST.BOOL", "TEST_ENV_BOOL", false);
    }

    void TearDown() override
    {
        // check pending expectations
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(m_fileLoader.get()));

        m_conf.reset();
        m_fileLoader.reset();
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

INSTANTIATE_TEST_SUITE_P(
    ConfLoadAndValidate,
    CustomConfValidate,
    ::testing::Values(
        // Success
        // std::make_tuple(conf::OptionMap {}, false),
        std::make_tuple(conf::OptionMap {{"TEST.INT", "10"}}, false),
        std::make_tuple(conf::OptionMap {{"TEST.INT64", "10"}}, false),
        std::make_tuple(conf::OptionMap {{"TEST.STRING", "test"}}, false),
        std::make_tuple(conf::OptionMap {{"TEST.STRING_LIST", "hello"}}, false), // Single value on list
        std::make_tuple(conf::OptionMap {{"TEST.STRING_LIST", "123"}}, false), // Single numeric string value on list
        std::make_tuple(conf::OptionMap {{"TEST.STRING_LIST", "hello, world"}}, false),
        std::make_tuple(conf::OptionMap {{"TEST.BOOL", "true"}}, false),
        std::make_tuple(conf::OptionMap {{"TEST.BOOL", "false"}}, false),

        // Failure
        // Invalid int
        std::make_tuple(conf::OptionMap {{"TEST.INT", "invalid"}}, true),
        std::make_tuple(conf::OptionMap {{"TEST.INT", "10.0"}}, true),
        std::make_tuple(conf::OptionMap {{"TEST.INT", "9223372036854775808"}}, true), // Out of range
        std::make_tuple(conf::OptionMap {{"TEST.INT", "true"}}, true),
        std::make_tuple(conf::OptionMap {{"TEST.INT", "10, 11"}}, true),
        // Invalid int64
        std::make_tuple(conf::OptionMap {{"TEST.INT64", "invalid"}}, true),
        std::make_tuple(conf::OptionMap {{"TEST.INT64", "10.0"}}, true),
        std::make_tuple(conf::OptionMap {{"TEST.INT64", "9223372036854775808"}}, true), // Out of range
        std::make_tuple(conf::OptionMap {{"TEST.INT64", "true"}}, true),
        std::make_tuple(conf::OptionMap {{"TEST.INT64", "10, 11"}}, true),
        // Invalid string list
        std::make_tuple(conf::OptionMap {{"TEST.STRING_LIST", "[hello, world]"}}, true),
        // Invalid bool
        std::make_tuple(conf::OptionMap {{"TEST.BOOL", "invalid"}}, true),
        std::make_tuple(conf::OptionMap {{"TEST.BOOL", "10"}}, true),
        std::make_tuple(conf::OptionMap {{"TEST.BOOL", "[true]"}}, true),
        std::make_tuple(conf::OptionMap {{"TEST.BOOL", "true, false"}}, true)));

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
    ON_FILE_LOAD, ///< Expected failure on load (Data validation)
    ON_GET,       ///< Expected failure on get (Data validation)
    NONE          ///< No expected failure
};

template<typename T>
class CustomConfPriorityTypeT
    : public ::testing::TestWithParam<std::tuple<T, conf::OptionMap, std::optional<std::string>, T, ExpFailType>>
{
protected:
    std::shared_ptr<conf::IFileLoader> m_fileLoader;
    std::shared_ptr<conf::Conf> m_conf;

    void SetUp() override
    {
        logging::testInit();
        // Unset standalone mode to ensure file loader is called
        unsetenv(base::process::ENV_ENGINE_STANDALONE);

        const auto& optionMap = std::get<1>(this->GetParam());
        m_fileLoader = conf::mocks::createMockFileLoader(optionMap);
        m_conf = std::make_shared<conf::Conf>(m_fileLoader);

        // Add the configuration units
        m_conf->addUnit("TEST", "TEST_ENV", std::get<0>(this->GetParam()));

        // Set the environment variable
        if (std::get<2>(this->GetParam()))
        {
            setEnv("TEST_ENV", *std::get<2>(this->GetParam()));
        }

        // Load the configuration
        if (std::get<4>(this->GetParam()) == ExpFailType::ON_FILE_LOAD)
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
        EXPECT_TRUE(testing::Mock::VerifyAndClearExpectations(m_fileLoader.get()));

        // Unset the environment variable
        unsetEnv("TEST_ENV");

        // Restore standalone mode for other tests
        setenv(base::process::ENV_ENGINE_STANDALONE, "true", 1);

        m_conf.reset();
        m_fileLoader.reset();
    }

    void runTest()
    {
        const auto& expectException = std::get<4>(this->GetParam());

        switch (expectException)
        {
            case ExpFailType::ON_FILE_LOAD: return;
            case ExpFailType::ON_GET: EXPECT_THROW(m_conf->get<T>("TEST"), std::runtime_error); break;
            case ExpFailType::NONE: EXPECT_EQ(m_conf->get<T>("TEST"), std::get<3>(this->GetParam())); break;
            default: FAIL() << "Unexpected expected failure";
        }
    }
};

using CustomConfPriorityInt = CustomConfPriorityTypeT<int>;
TEST_P(CustomConfPriorityInt, PriorityInt)
{
    runTest();
}

INSTANTIATE_TEST_SUITE_P(
    ConfPriorityInt,
    CustomConfPriorityInt,
    ::testing::Values(
        // Default value | Option map | Environment variable | Expected value | Expected failure
        // Success
        std::make_tuple(10, conf::OptionMap {}, std::nullopt, 10, ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {}, "20", 20, ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {{"TEST", "20"}}, std::nullopt, 20, ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {{"TEST", "20"}}, "30", 30, ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {}, "invalid", 10, ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {{"TEST", "20"}}, "invalid", 20, ExpFailType::NONE),
        // Failure on load the configuration (Data validation)
        std::make_tuple(10, conf::OptionMap {{"TEST", "invalid"}}, std::nullopt, 10, ExpFailType::ON_FILE_LOAD),
        std::make_tuple(10, conf::OptionMap {{"TEST", "false"}}, std::nullopt, 10, ExpFailType::ON_FILE_LOAD)
        // END
        ));

using CustomConfPriorityInt64 = CustomConfPriorityTypeT<int64_t>;
TEST_P(CustomConfPriorityInt64, PriorityInt64)
{
    runTest();
}

INSTANTIATE_TEST_SUITE_P(
    ConfPriorityInt64,
    CustomConfPriorityInt64,
    ::testing::Values(
        // Default value | Option Map | Environment variable | Expected value | Expected failure
        // Success
        std::make_tuple(10, conf::OptionMap {}, std::nullopt, 10, ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {}, "20", 20, ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {{"TEST", "20"}}, std::nullopt, 20, ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {{"TEST", "20"}}, "30", 30, ExpFailType::NONE),
        std::make_tuple(std::numeric_limits<int64_t>::min(),
                        conf::OptionMap {},
                        std::nullopt,
                        std::numeric_limits<int64_t>::min(),
                        ExpFailType::NONE),
        std::make_tuple(std::numeric_limits<int64_t>::min(),
                        conf::OptionMap {{"TEST", "9223372036854775807"}},
                        std::nullopt,
                        9223372036854775807,
                        ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {}, "invalid", 10, ExpFailType::NONE),
        std::make_tuple(10, conf::OptionMap {{"TEST", "20"}}, "invalid", 20, ExpFailType::NONE),
        // Failure on load the configuration (Data validation)
        std::make_tuple(10, conf::OptionMap {{"TEST", "invalid"}}, std::nullopt, 10, ExpFailType::ON_FILE_LOAD),
        std::make_tuple(10, conf::OptionMap {{"TEST", "false"}}, std::nullopt, 10, ExpFailType::ON_FILE_LOAD)
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
                             // Default value | Option Map | Environment variable | Expected value | Expected failure
                             // Success
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             conf::OptionMap {},
                                             std::nullopt,
                                             std::vector<std::string> {"hello", "world"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             conf::OptionMap {},
                                             "hello,world",
                                             std::vector<std::string> {"hello", "world"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             conf::OptionMap {{"TEST", "hello, world2"}},
                                             std::nullopt,
                                             std::vector<std::string> {"hello", "world2"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             conf::OptionMap {{"TEST", "hello, world"}},
                                             "world,hello,yes",
                                             std::vector<std::string> {"world", "hello", "yes"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             conf::OptionMap {},
                                             "hello",
                                             std::vector<std::string> {"hello"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             conf::OptionMap {},
                                             "hello,10",
                                             std::vector<std::string> {"hello", "10"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             conf::OptionMap {},
                                             R"(hello[],world)",
                                             std::vector<std::string> {"hello[]", "world"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             conf::OptionMap {},
                                             R"([hello,world])",
                                             std::vector<std::string> {"hello", "world"},
                                             ExpFailType::NONE),
                             std::make_tuple(std::vector<std::string> {"hello", "world"},
                                             conf::OptionMap {{"TEST", "hello"}},
                                             std::nullopt,
                                             std::vector<std::string> {"hello"},
                                             ExpFailType::NONE)
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
        // Default value | Option Map | Environment variable | Expected value | Expected failure
        // Success
        std::make_tuple(false, conf::OptionMap {}, std::nullopt, false, ExpFailType::NONE),
        std::make_tuple(false, conf::OptionMap {}, "true", true, ExpFailType::NONE),
        std::make_tuple(false, conf::OptionMap {{"TEST", "true"}}, std::nullopt, true, ExpFailType::NONE),
        std::make_tuple(false, conf::OptionMap {{"TEST", "true"}}, "false", false, ExpFailType::NONE),
        std::make_tuple(true, conf::OptionMap {{"TEST", "true"}}, "false", false, ExpFailType::NONE),
        std::make_tuple(false, conf::OptionMap {}, "invalid", false, ExpFailType::NONE),
        std::make_tuple(false, conf::OptionMap {{"TEST", "true"}}, "invalid", true, ExpFailType::NONE),
        // Failure on load the configuration (Data validation)
        std::make_tuple(false, conf::OptionMap {{"TEST", "invalid"}}, std::nullopt, false, ExpFailType::ON_FILE_LOAD),
        std::make_tuple(false, conf::OptionMap {{"TEST", "10"}}, std::nullopt, false, ExpFailType::ON_FILE_LOAD),
        std::make_tuple(false, conf::OptionMap {{"TEST", "null"}}, std::nullopt, false, ExpFailType::ON_FILE_LOAD)
        // END
        ));

TEST(ConfGet, invalidType)
{
    logging::testInit();
    // Bad type, should throw a logic error, add INT get DOUBLE
    conf::Conf conf(std::make_shared<conf::mocks::MockFileLoader>());
    conf.addUnit("/TEST", "TEST_ENV", 10);
    EXPECT_THROW(conf.get<double>("/TEST"), std::logic_error);
}

TEST(ConfGet, badKey)
{

    conf::Conf conf(std::make_shared<conf::mocks::MockFileLoader>());

    EXPECT_THROW(conf.get<int>("/TEST"), std::runtime_error);
}
} // namespace
