#include <any>
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

namespace
{
using namespace base;
using namespace metricsManager;
using namespace builder::internals::builders;

template<typename T>
class KVDBNotMatchHelper : public ::testing::TestWithParam<T>
{

protected:
    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager;
    std::shared_ptr<defs::mocks::FailDef> m_failDef;
    builder::internals::HelperBuilder m_builder;

    void SetUp() override
    {
        logging::testInit();

        m_manager = std::make_shared<FakeMetricManager>();
        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
        m_failDef = std::make_shared<defs::mocks::FailDef>();

        m_builder = getOpBuilderKVDBNotMatch(m_kvdbManager, "builder_test");
    }

    void TearDown() override {}
};

} // namespace

using NotMatchParamsT = std::tuple<std::vector<std::string>, bool>;
class NotMatchParams : public KVDBNotMatchHelper<NotMatchParamsT>
{
};

// Test of build params
TEST_P(NotMatchParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_not_match";

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

INSTANTIATE_TEST_SUITE_P(KVDBNotMatch,
                         NotMatchParams,
                         ::testing::Values(
                             // Ok
                             NotMatchParamsT({DB_NAME_1}, true),
                             // bad size
                             NotMatchParamsT({DB_NAME_1, "test"}, false),
                             NotMatchParamsT({DB_NAME_1, "test", "test2"}, false),
                             NotMatchParamsT({DB_NAME_1, "test", "$test2"}, false),
                             // bad params
                             NotMatchParamsT(std::vector<std::string>(), false)));

using NotMatchBadParamsT = std::tuple<std::vector<std::string>>;
class NotMatchBadParams : public KVDBNotMatchHelper<NotMatchBadParamsT>
{
};

// Test of bad params
TEST_P(NotMatchBadParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_not_match";

    auto [params] = GetParam();

    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test"))
        .WillOnce(testing::Return(kvdb::mocks::kvdbGetKVDBHandlerError("")));
    ASSERT_THROW(m_builder(targetField, rawName, params, m_failDef), std::runtime_error);
}

INSTANTIATE_TEST_SUITE_P(KVDBNotMatch,
                         NotMatchBadParams,
                         ::testing::Values(
                             // bad params
                             NotMatchBadParamsT({"unknow_database"})));

class NotMatchKey : public KVDBNotMatchHelper<NotMatchParamsT>
{
};

// Test of match function
TEST_P(NotMatchKey, matching)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_not_match";
    const std::string field = "key_founded";

    auto [params, shouldPass] = GetParam();
    auto event = std::make_shared<json::Json>(R"({"field": "key_founded"})");

    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test")).WillOnce(testing::Return(kvdbHandler));
    auto op = m_builder(targetField, rawName, params, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();

    result::Result<Event> resultEvent;

    if (shouldPass)
    {
        EXPECT_CALL(*kvdbHandler, contains(field)).WillOnce(testing::Return(kvdb::mocks::kvdbContainsNOk()));
        ASSERT_NO_THROW(resultEvent = op(event));
        ASSERT_TRUE(resultEvent.success());
    }
    else
    {
        EXPECT_CALL(*kvdbHandler, contains(field)).WillOnce(testing::Return(kvdb::mocks::kvdbContainsOk()));
        ASSERT_NO_THROW(resultEvent = op(event));
        ASSERT_TRUE(resultEvent.failure());
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBNotMatch,
                         NotMatchKey,
                         ::testing::Values(
                             // OK
                             NotMatchParamsT({DB_NAME_1}, true),
                             // NOK
                             NotMatchParamsT({DB_NAME_1}, false)));
