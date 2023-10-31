#include <any>
#include <filesystem>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <json/json.hpp>
#include <opBuilderKVDB.hpp>
#include <testsCommon.hpp>

#include <kvdb/mockKvdbHandler.hpp>
#include <kvdb/mockKvdbManager.hpp>
#include <mocks/fakeMetric.hpp>

namespace
{
using namespace base;
using namespace metricsManager;
using namespace builder::internals::builders;

using json::Json;
using std::string;
using std::vector;

static constexpr auto DB_NAME_1 = "TEST_DB_1";
static constexpr auto DB_DIR = "/tmp/kvdbTestSuitePath/";
static constexpr auto DB_NAME = "kvdb";

template<typename T>
class KVDBDeleteHelper : public ::testing::TestWithParam<T>
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

        m_failDef = std::make_shared<defs::mocks::FailDef>();
        m_manager = std::make_shared<FakeMetricManager>();
        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();

        m_builder = getOpBuilderKVDBDelete(m_kvdbManager, "builder_test");
    }

    void TearDown() override
    {
        try
        {
            m_kvdbManager->finalize();
        }
        catch (const std::exception& e)
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

using DeleteParamsT = std::tuple<std::vector<std::string>, bool>;
class DeleteParams : public KVDBDeleteHelper<DeleteParamsT>
{
};

// Test of build params
TEST_P(DeleteParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_delete";

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

INSTANTIATE_TEST_SUITE_P(KVDBDelete,
                         DeleteParams,
                         ::testing::Values(
                             // OK
                             DeleteParamsT({DB_NAME_1, "key"}, true),
                             DeleteParamsT({DB_NAME_1, "$key"}, true),
                             // NOK
                             DeleteParamsT({DB_NAME_1, "test", "test2"}, false),
                             DeleteParamsT({DB_NAME_1, "test", "$test2"}, false),
                             DeleteParamsT({DB_NAME_1}, false),
                             DeleteParamsT({}, false)));

using DeleteKeyT = std::tuple<std::vector<std::string>, bool, std::string>;
class DeleteKey : public KVDBDeleteHelper<DeleteKeyT>
{
protected:
    void SetUp() override { KVDBDeleteHelper<DeleteKeyT>::SetUp(); }
};

// Test of delete function
TEST_P(DeleteKey, deleting)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_delete";

    auto [params, shouldPass, rawEvent] = GetParam();
    auto event = std::make_shared<json::Json>(rawEvent.c_str());

    result::Result<Event> resultEvent;

    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*kvdbHandler, get(params[1])).WillRepeatedly(testing::Return(rawEvent));

    if (shouldPass)
    {
        EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test"))
            .WillRepeatedly(testing::Return(kvdbHandler));
        auto op = m_builder(targetField, rawName, params, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();
        ASSERT_NO_THROW(resultEvent = op(event));
        ASSERT_TRUE(resultEvent.success());
    }
    else
    {
        EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test"))
            .WillRepeatedly(testing::Return(kvdb::mocks::kvdbGetKVDBHandlerError("")));
        ASSERT_THROW(
            auto op = m_builder(targetField, rawName, params, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn(),
            std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBDelete,
                         DeleteKey,
                         ::testing::Values(
                             // OK
                             DeleteKeyT({DB_NAME_1, "key1"}, true, R"({"result": ""})"),
                             DeleteKeyT({DB_NAME_1, "KEY2"}, true, R"({"result": ""})"),
                             DeleteKeyT({DB_NAME_1, "key_"}, true, R"({"result": ""})"),
                             DeleteKeyT({DB_NAME_1, "$key"}, true, R"({"key":"key3", "result": ""})"),
                             // NOK
                             DeleteKeyT({"unknow_database", "key1"}, false, R"({"result": ""})")));
