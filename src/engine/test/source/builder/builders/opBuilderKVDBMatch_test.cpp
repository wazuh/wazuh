#include <any>
#include <filesystem>
#include <memory>
#include <vector>

#include <gtest/gtest.h>
#include <json/json.hpp>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <kvdb/mockKvdbHandler.hpp>
#include <kvdb/mockKvdbManager.hpp>
#include <mocks/fakeMetric.hpp>
#include <opBuilderKVDB.hpp>
#include <testsCommon.hpp>

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
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager;
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
        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
        m_failDef = std::make_shared<defs::mocks::FailDef>();

        m_builder = getOpBuilderKVDBMatch(m_kvdbManager, "builder_test");
    }

    void TearDown() override
    {
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

    auto [params, shouldPass] = GetParam();

    if (shouldPass)
    {
        auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
        EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test")).WillOnce(testing::Return(kvdbHandler));
        ASSERT_NO_THROW(m_builder(targetField, rawName, params, m_failDef));
    }
    else
    {
        ASSERT_THROW(m_builder(targetField, rawName, params, m_failDef), std::runtime_error);
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
                             MatchParamsT({DB_NAME_1, "test", "$test2"}, false),
                             // bad params,
                             MatchParamsT({}, false)));

using MatchBadParamsT = std::tuple<std::vector<std::string>>;
class MatchBadParams : public KVDBMatchHelper<MatchBadParamsT>
{
};

// Test of bad params
TEST_P(MatchBadParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_match";

    auto [params] = GetParam();

    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test"))
        .WillOnce(testing::Return(kvdb::mocks::kvdbGetKVDBHandlerError("")));
    ASSERT_THROW(m_builder(targetField, rawName, params, m_failDef), std::runtime_error);
}

INSTANTIATE_TEST_SUITE_P(KVDBMatch,
                         MatchBadParams,
                         ::testing::Values(
                             // bad params
                             MatchBadParamsT({"unknow_database"})));

class MatchKey : public KVDBMatchHelper<MatchParamsT>
{
};

// Test of match function
TEST_P(MatchKey, matching)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_match";
    const std::string field = "key_founded";

    auto [params, shouldPass] = GetParam();
    auto event = std::make_shared<json::Json>(R"({"field": "key_founded"})");

    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test")).WillOnce(testing::Return(kvdbHandler));
    auto op = m_builder(targetField, rawName, params, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();

    result::Result<Event> resultEvent;

    if (shouldPass)
    {
        EXPECT_CALL(*kvdbHandler, contains(field)).WillOnce(testing::Return(kvdb::mocks::kvdbContainsOk()));
        ASSERT_NO_THROW(resultEvent = op(event));
        ASSERT_TRUE(resultEvent.success());
    }
    else
    {
        EXPECT_CALL(*kvdbHandler, contains(field)).WillOnce(testing::Return(kvdb::mocks::kvdbContainsNOk()));
        ASSERT_NO_THROW(resultEvent = op(event));
        ASSERT_TRUE(resultEvent.failure());
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBMatch,
                         MatchKey,
                         ::testing::Values(
                             // OK
                             MatchParamsT({DB_NAME_1}, true),
                             // NOK
                             MatchParamsT({DB_NAME_1}, false)));
