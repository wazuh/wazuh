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

namespace
{
using namespace base;
using namespace metricsManager;
using namespace builder::internals::builders;

using json::Json;
using std::string;
using std::vector;

static constexpr auto DB_NAME_1 = "test_db";

template<typename T>
class KVDBSetHelper : public ::testing::TestWithParam<T>
{
protected:
    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager;
    builder::internals::HelperBuilder m_builder;
    std::shared_ptr<defs::mocks::FailDef> m_failDef;

    void SetUp() override
    {
        logging::testInit();

        m_manager = std::make_shared<FakeMetricManager>();
        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
        m_failDef = std::make_shared<defs::mocks::FailDef>();

        m_builder = getOpBuilderKVDBSet(m_kvdbManager, "builder_test");
    }

    void TearDown() override {}
};
} // namespace

using SetParamsT = std::tuple<std::vector<std::string>, bool>;
class SetParams : public KVDBSetHelper<SetParamsT>
{
};

// Test of build params
TEST_P(SetParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_set";

    auto [params, shouldPass] = GetParam();

    if (shouldPass)
    {
        auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
        EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test"))
            .WillOnce(testing::Return(kvdbHandler));
        ASSERT_NO_THROW(m_builder(targetField, rawName, params, m_failDef));
    }
    else
    {
        ASSERT_THROW(m_builder(targetField, rawName, params, m_failDef), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBSet,
                         SetParams,
                         ::testing::Values(
                             // OK
                             SetParamsT({DB_NAME_1, "key", "value"}, true),
                             SetParamsT({DB_NAME_1, "key", ""}, true),
                             SetParamsT({DB_NAME_1, "$key", "value"}, true),
                             SetParamsT({DB_NAME_1, "$key", ""}, true),
                             // NOK
                             SetParamsT({DB_NAME_1}, false),
                             SetParamsT({DB_NAME_1, "key"}, false),
                             SetParamsT({DB_NAME_1, "$key"}, false),
                             SetParamsT(std::vector<std::string>(), false)));

using SetBadParamsT = std::tuple<std::vector<std::string>>;
class SetBadParams : public KVDBSetHelper<SetBadParamsT>
{
};

// Test of bad params
TEST_P(SetBadParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_match";
    auto [params] = GetParam();

    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test"))
        .WillOnce(testing::Return(kvdb::mocks::kvdbGetKVDBHandlerError("")));
    ASSERT_THROW(m_builder(targetField, rawName, params, m_failDef), std::runtime_error);
}

INSTANTIATE_TEST_SUITE_P(KVDBSet,
                         SetBadParams,
                         ::testing::Values(
                             // bad params
                             SetBadParamsT({"unknow_database", "key", "value"})));

using SetKeyT = std::tuple<std::vector<std::string>, std::string, std::string>;
class SetKey : public KVDBSetHelper<SetKeyT>
{
};

// Test of set function
TEST_P(SetKey, setting)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_set";

    auto [params, rawEvent, key] = GetParam();
    auto event = std::make_shared<json::Json>(rawEvent.c_str());
    result::Result<Event> resultEvent;
    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test"))
        .WillOnce(testing::Return(kvdbHandler));
    EXPECT_CALL(*kvdbHandler, set(key, params[2])).WillOnce(testing::Return(kvdb::mocks::kvdbSetOk()));
    auto op = m_builder(targetField, rawName, params, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();
    ASSERT_NO_THROW(resultEvent = op(event));
    ASSERT_TRUE(resultEvent.success());
}

INSTANTIATE_TEST_SUITE_P(KVDBSet,
                         SetKey,
                         ::testing::Values(
                             // OK
                             SetKeyT({DB_NAME_1, "key", "value"}, R"({"result": ""})", "key"),
                             SetKeyT({DB_NAME_1, "KEY2", ""}, R"({"result": ""})", "KEY2"),
                             SetKeyT({DB_NAME_1, "", "value"}, R"({"result": ""})", ""),
                             SetKeyT({DB_NAME_1, "$key", "value"}, R"({"result": "", "key": "key3"})", "key3")));
