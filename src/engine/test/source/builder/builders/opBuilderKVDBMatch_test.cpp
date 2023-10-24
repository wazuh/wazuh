#include <any>
#include <memory>
#include <vector>

#include <gtest/gtest.h>
#include <json/json.hpp>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <kvdb/kvdbManager.hpp>
#include <opBuilderKVDB.hpp>
#include <testsCommon.hpp>

#include <mocks/fakeMetric.hpp>

constexpr auto DB_NAME_1 = "TEST_DB";
constexpr auto DB_DIR = "/tmp/kvdbTestSuitePath/";
constexpr auto DB_NAME = "kvdb";

namespace
{
using namespace base;
using namespace metricsManager;
using namespace builder::internals::builders;

template<typename T>
class KVDBMatchHelper : public ::testing::TestWithParam<T>
{

protected:
    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdbManager::IKVDBManager> m_kvdbManager;
    std::shared_ptr<defs::mocks::FailDef> m_failDef;
    builder::internals::HelperBuilder m_builder;
    std::string kvdbPath;

    void SetUp() override
    {
        logging::testInit();

        // cleaning directory in order to start without garbage.
        kvdbPath = generateRandomStringWithPrefix(6, DB_DIR) + "/";

        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }

        m_manager = std::make_shared<FakeMetricManager>();
        kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, DB_NAME};
        m_kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, m_manager);

        m_kvdbManager->initialize();

        auto err = m_kvdbManager->createDB(DB_NAME_1);
        ASSERT_FALSE(err);
        auto result = m_kvdbManager->getKVDBHandler(DB_NAME_1, "builder_test");
        ASSERT_FALSE(std::holds_alternative<base::Error>(result));

        m_builder = getOpBuilderKVDBMatch(m_kvdbManager, "builder_test");
    }

    void TearDown() override
    {
        try
        {
            m_kvdbManager->finalize();
        }
        catch (std::exception& e)
        {
            FAIL() << "Exception: " << e.what();
        }

        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }
    }
};

} // namespace

using MatchParamsT = std::tuple<std::vector<std::string>, bool>;
class MatchParams : public KVDBMatchHelper<MatchParamsT>
{
};

// Test of build params
TEST_P(MatchParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_match";

    auto [parameters, shouldPass] = GetParam();

    if (shouldPass)
    {
        ASSERT_NO_THROW(m_builder(targetField, rawName, parameters, m_failDef));
    }
    else
    {
        ASSERT_THROW(m_builder(targetField, rawName, parameters, m_failDef), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBMatch,
                         MatchParams,
                         ::testing::Values(
                             // Ok
                             MatchParamsT({DB_NAME_1}, true),
                             // bad size
                             MatchParamsT({DB_NAME_1, "test"}, false),
                             MatchParamsT({DB_NAME_1, "test", "test2"}, false),
                             MatchParamsT({}, false)));

using MatchKeyT = std::tuple<std::string, std::vector<std::string>, bool, std::string>;
class MatchKey : public KVDBMatchHelper<MatchKeyT>
{
protected:
    void SetUp() override
    {
        KVDBMatchHelper<MatchKeyT>::SetUp();

        // Insert initial state to DB
        auto handler = base::getResponse<std::shared_ptr<kvdbManager::IKVDBHandler>>(
            m_kvdbManager->getKVDBHandler(DB_NAME_1, "test"));

        ASSERT_FALSE(handler->set("key1", "value"));
        ASSERT_FALSE(handler->set("key_founded", "value"));
        ASSERT_FALSE(handler->set("key2", "value"));
    }
};

// Test of match function
TEST_P(MatchKey, matching)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_match";

    auto [raw_event, parameters, shouldPass, expected] = GetParam();
    auto event = std::make_shared<json::Json>(raw_event.c_str());

    auto op = m_builder(targetField, rawName, parameters, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();

    result::Result<Event> resultEvent;
    ASSERT_NO_THROW(resultEvent = op(event));

    if (shouldPass)
    {
        ASSERT_TRUE(resultEvent.success());
        auto value = resultEvent.payload()->getString("/field").value();
        ASSERT_EQ(value, expected);
    }
    else
    {
        ASSERT_TRUE(resultEvent.failure());
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBMatch,
                         MatchKey,
                         ::testing::Values(
                             // OK
                             MatchKeyT(R"({"field": "key_founded"})", {DB_NAME_1}, true, "key_founded"),
                             // NOK
                             MatchKeyT(R"({"field": "key_found"})", {DB_NAME_1}, false, ""),
                             MatchKeyT(R"({"field": "key"})", {DB_NAME_1}, false, ""),
                             MatchKeyT(R"({"field": "key_"})", {DB_NAME_1}, false, ""),
                             MatchKeyT(R"({"field": "not_found"})", {DB_NAME_1}, false, ""),
                             MatchKeyT(R"({"field": ""})", {DB_NAME_1}, false, "")));