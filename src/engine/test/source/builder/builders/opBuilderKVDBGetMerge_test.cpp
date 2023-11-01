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

namespace
{
using namespace base;
using namespace metricsManager;
using namespace builder::internals::builders;

static constexpr auto DB_NAME_1 = "TEST_DB_1";
static constexpr auto DB_DIR = "/tmp/kvdbTestSuitePath/";
static constexpr auto DB_NAME = "kvdb";

template<typename T>
class KVDBGetHelper : public ::testing::TestWithParam<T>
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

        m_builder = getOpBuilderKVDBGetMerge(m_kvdbManager, "builder_test");
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

using GetParamsT = std::tuple<std::vector<std::string>, bool>;
using GetKeyT = std::tuple<std::vector<std::string>, bool, std::string, std::string, std::string, std::string>;

class GetMergeParams : public KVDBGetHelper<GetParamsT>
{
    void SetUp() override
    {
        KVDBGetHelper<GetParamsT>::SetUp();
        m_builder = getOpBuilderKVDBGetMerge(m_kvdbManager, "builder_test");
    }
};

// Test of build params
TEST_P(GetMergeParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_get_merge";

    auto [params, shouldPass] = GetParam();
    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();

    if (shouldPass)
    {
        EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test")).WillOnce(testing::Return(kvdbHandler));
        ASSERT_NO_THROW(m_builder(targetField, rawName, params, m_failDef));
    }
    else
    {
        ASSERT_THROW(m_builder(targetField, rawName, params, m_failDef), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBGetMerge,
                         GetMergeParams,
                         ::testing::Values(
                             // OK
                             GetParamsT({DB_NAME_1, "key"}, true),
                             GetParamsT({DB_NAME_1, "$key"}, true),
                             // NOK
                             GetParamsT({DB_NAME_1, "test", "test2"}, false),
                             GetParamsT({DB_NAME_1, "test", "$test2"}, false),
                             GetParamsT({DB_NAME_1}, false),
                             GetParamsT({}, false)));

class GetMergeKey : public KVDBGetHelper<GetKeyT>
{
protected:
    void SetUp() override { KVDBGetHelper<GetKeyT>::SetUp(); }
};

// Test of get function
TEST_P(GetMergeKey, getting)
{
    const std::string targetField = "/result";
    const std::string rawName = "kvdb_get_merge";

    auto [params, shouldPass, key, rawEvent, rawResult, rawExpected] = GetParam();
    auto event = std::make_shared<json::Json>(rawEvent.c_str());
    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test")).WillOnce(testing::Return(kvdbHandler));
    auto op = m_builder(targetField, rawName, params, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();

    result::Result<Event> resultEvent;

    if (shouldPass)
    {
        EXPECT_CALL(*kvdbHandler, get(key)).WillRepeatedly(testing::Return(kvdb::mocks::kvdbGetOk(rawResult)));
        ASSERT_NO_THROW(resultEvent = op(event));
        auto jsonExpected = std::make_shared<json::Json>(rawExpected.c_str());
        ASSERT_TRUE(resultEvent.success());
        ASSERT_EQ(*resultEvent.payload(), *jsonExpected);
    }
    else
    {
        ASSERT_NO_THROW(resultEvent = op(event));
        ASSERT_TRUE(resultEvent.failure());
    }
}

INSTANTIATE_TEST_SUITE_P(
    KVDBGetMerge,
    GetMergeKey,
    ::testing::Values(
        // OK
        GetKeyT({DB_NAME_1, "keyObject"},
                true,
                "keyObject",
                R"({"result": {"field0": "value0"}})",
                R"({"field0":"value0","field1":"value1","field2":"value2","field3":"value3"})",
                R"({"result":{"field0":"value0","field1":"value1","field2":"value2","field3":"value3"}})"),
        GetKeyT({DB_NAME_1, "keyArray"},
                true,
                "keyArray",
                R"({"result": ["value0"]})",
                R"(["value0", "value1", "value2", "value3"])",
                R"({"result": ["value0", "value1", "value2", "value3"]})"),
        GetKeyT(
            {DB_NAME_1, "$keyObject"},
            true,
            "keyObject",
            R"({"keyObject": "keyObject", "result": {"field0": "value0"}})",
            R"({"field0":"value0","field1":"value1","field2":"value2","field3":"value3"})",
            R"({"keyObject":"keyObject", "result":{"field0":"value0","field1":"value1","field2":"value2","field3":"value3"}})"),
        GetKeyT({DB_NAME_1, "$keyArray"},
                true,
                "keyArray",
                R"({"keyArray": "keyArray", "result": ["value0"]})",
                R"(["value0", "value1", "value2", "value3"])",
                R"({"keyArray": "keyArray", "result": ["value0", "value1", "value2", "value3"]})"),
        // NOK
        GetKeyT({DB_NAME_1, "keyObject"},
                false,
                "keyObject",
                R"({"other_result": {"field0": "value0"}})",
                R"()",
                R"({"result":{"field0":"value0","field1":"value1","field2":"value2","field3":"value3"}})"),
        GetKeyT({DB_NAME_1, "keyArray"},
                false,
                "keyArray",
                R"({"other_result": ["value0"]})",
                R"()",
                R"({"result": ["value0", "value1", "value2", "value3"]})"),
        GetKeyT({DB_NAME_1, "$keyArray"},
                false,
                "keyArray",
                R"({"other_result": ["value0"]})",
                R"()",
                R"({"result": ["value0", "value1", "value2", "value3"]})"),
        GetKeyT({DB_NAME_1, "keyString"}, false, "keyString", R"({})", R"()", R"({})"),
        GetKeyT({DB_NAME_1, "KEY2"}, false, "KEY2", R"({})", R"()", R"({})"),
        GetKeyT({DB_NAME_1, "key_"}, false, "key_", R"({})", R"()", R"({})"),
        GetKeyT({DB_NAME_1, ""}, false, "", R"({})", R"()", R"({})")));
