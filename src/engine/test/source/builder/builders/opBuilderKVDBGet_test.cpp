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

static constexpr auto DB_NAME_1 = "TEST_DB_1";

template<typename T>
class KVDBGetHelper : public ::testing::TestWithParam<T>
{
protected:
    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager;
    std::shared_ptr<defs::mocks::FailDef> m_failDef;
    builder::internals::HelperBuilder m_builder;

    void SetUp() override
    {
        logging::testInit();

        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
        m_manager = std::make_shared<FakeMetricManager>();
        m_failDef = std::make_shared<defs::mocks::FailDef>();

        m_builder = getOpBuilderKVDBGet(m_kvdbManager, "builder_test");
    }

    void TearDown() override
    {
    }
};
} // namespace

using GetParamsT = std::tuple<std::vector<std::string>, bool>;
class GetParams : public KVDBGetHelper<GetParamsT>
{
};

// Test of build params
TEST_P(GetParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_get";

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

INSTANTIATE_TEST_SUITE_P(KVDBGet,
                         GetParams,
                         ::testing::Values(
                             // OK
                             GetParamsT({DB_NAME_1, "key"}, true),
                             GetParamsT({DB_NAME_1, "$key"}, true),
                             // NOK
                             GetParamsT({DB_NAME_1, "test", "test2"}, false),
                             GetParamsT({DB_NAME_1, "test", "$test2"}, false),
                             GetParamsT({DB_NAME_1}, false),
                             GetParamsT(std::vector<std::string>(), false)));

using GetKeyT = std::tuple<std::vector<std::string>, bool, std::string, std::string, std::string>;
class GetKey : public KVDBGetHelper<GetKeyT>
{
};

// Test of get function
TEST_P(GetKey, getting)
{
    const std::string targetField = "/result";
    const std::string rawName = "kvdb_get";

    auto [params, shouldPass, rawEvent, rawResult, rawExpected] = GetParam();
    auto event = std::make_shared<json::Json>(rawEvent.c_str());

    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test")).WillOnce(testing::Return(kvdbHandler));

    result::Result<Event> resultEvent;

    if (shouldPass)
    {
        EXPECT_CALL(*kvdbHandler, get(testing::_)).WillRepeatedly(testing::Return(kvdb::mocks::kvdbGetOk(rawResult)));
        auto op = m_builder(targetField, rawName, params, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();
        auto jsonExpected = std::make_shared<json::Json>(rawExpected.c_str());
        ASSERT_NO_THROW(resultEvent = op(event));
        ASSERT_TRUE(resultEvent.success());
        ASSERT_EQ(*resultEvent.payload(), *jsonExpected);
    }
    else
    {
        EXPECT_CALL(*kvdbHandler, get(testing::_))
            .WillRepeatedly(testing::Return(kvdb::mocks::kvdbGetError(rawResult)));
        auto op = m_builder(targetField, rawName, params, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();
        ASSERT_NO_THROW(resultEvent = op(event));
        ASSERT_TRUE(resultEvent.failure());
    }
}

INSTANTIATE_TEST_SUITE_P(
    KVDBGet,
    GetKey,
    ::testing::Values(
        // OK
        GetKeyT({DB_NAME_1, "keyString"}, true, R"({})", R"("string_value")", R"({"result": "string_value"})"),
        GetKeyT({DB_NAME_1, "keyNumber"}, true, R"({})", R"(123)", R"({"result": 123})"),
        GetKeyT({DB_NAME_1, "keyObject"},
                true,
                R"({})",
                R"({"field1": "value1", "field2": "value2"})",
                R"({"result": {"field1": "value1", "field2": "value2"}})"),
        GetKeyT(
            {DB_NAME_1, "keyArray"}, true, R"({})", R"(["value1", "value2"])", R"({"result": ["value1", "value2"]})"),
        GetKeyT({DB_NAME_1, "keyNull"}, true, R"({})", R"(null)", R"({"result": null})"),
        GetKeyT({DB_NAME_1, "$keyString"},
                true,
                R"({"keyString": "keyString"})",
                R"("string_value")",
                R"({"keyString": "keyString","result": "string_value"})"),
        GetKeyT({DB_NAME_1, "$keyNumber"},
                true,
                R"({"keyNumber": "keyNumber"})",
                R"(123)",
                R"({"keyNumber": "keyNumber", "result": 123})"),
        GetKeyT({DB_NAME_1, "$keyObject"},
                true,
                R"({"keyObject": "keyObject"})",
                R"({"field1": "value1", "field2": "value2"})",
                R"({"keyObject": "keyObject", "result": {"field1": "value1", "field2": "value2"}})"),
        GetKeyT({DB_NAME_1, "$keyArray"},
                true,
                R"({"keyArray": "keyArray"})",
                R"(["value1", "value2"])",
                R"({"keyArray": "keyArray", "result": ["value1", "value2"]})"),
        GetKeyT({DB_NAME_1, "$keyNull"},
                true,
                R"({"keyNull": "keyNull"})",
                R"(null)",
                R"({"keyNull": "keyNull", "result": null})"),
        // NOK
        GetKeyT({DB_NAME_1, "KEY2"}, false, R"({})", R"({})", R"({})"),
        GetKeyT({DB_NAME_1, "key_"}, false, R"({})", R"({})", R"({})"),
        GetKeyT({DB_NAME_1, "$key"}, false, R"({})", R"({})", R"({})"),
        GetKeyT({DB_NAME_1, ""}, false, R"({})", R"({})", R"({})")));
