#include <gtest/gtest.h>

#include <any>
#include <memory>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <json/json.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <kvdb/kvdbManager.hpp>
#include <opBuilderKVDB.hpp>
#include <testsCommon.hpp>

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

        auto err1 = m_kvdbManager->createDB(DB_NAME_1);
        ASSERT_FALSE(err1);

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

INSTANTIATE_TEST_SUITE_P(KVDBDelete,
                         DeleteParams,
                         ::testing::Values(
                             // OK
                             DeleteParamsT({DB_NAME_1, "key"}, true),
                             // NOK
                             DeleteParamsT({DB_NAME_1, "test", "test2"}, false),
                             DeleteParamsT({DB_NAME_1}, false),
                             DeleteParamsT({}, false),
                             DeleteParamsT({"unknow_database", ""}, false)));

using DeleteKeyT = std::tuple<std::vector<std::string>, bool>;
class DeleteKey : public KVDBDeleteHelper<DeleteKeyT>
{
protected:
    void SetUp() override
    {
        KVDBDeleteHelper<DeleteKeyT>::SetUp();

        // Insert initial state to DB
        auto handler = base::getResponse<std::shared_ptr<kvdbManager::IKVDBHandler>>(
            m_kvdbManager->getKVDBHandler(DB_NAME_1, "test"));

        ASSERT_FALSE(handler->set("key1", "value"));
        ASSERT_FALSE(handler->set("key2", "value"));
        ASSERT_FALSE(handler->set("key3", "value"));
    }
};

// Test of delete function
TEST_P(DeleteKey, deleting)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_delete";

    auto [parameters, shouldPass] = GetParam();
    auto event = std::make_shared<json::Json>(R"({"result": ""})");

    auto op = m_builder(targetField, rawName, parameters, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();

    result::Result<Event> resultEvent;
    ASSERT_NO_THROW(resultEvent = op(event));

    if (shouldPass)
    {
        ASSERT_TRUE(resultEvent.success());
    }
    else
    {
        ASSERT_TRUE(resultEvent.failure());
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBDelete,
                         DeleteKey,
                         ::testing::Values(
                             // OK
                             DeleteKeyT({DB_NAME_1, "key1"}, true),
                             DeleteKeyT({DB_NAME_1, "KEY2"}, true),
                             DeleteKeyT({DB_NAME_1, "key_"}, true),
                             DeleteKeyT({DB_NAME_1, ""}, true)));
