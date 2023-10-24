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

namespace
{
using namespace base;
using namespace metricsManager;
using namespace builder::internals::builders;

using json::Json;
using std::string;
using std::vector;

static constexpr auto DB_NAME_1 = "test_db";
static constexpr auto DB_DIR = "/tmp/kvdbTestSuitePath/";
static constexpr auto DB_NAME = "kvdb";

template<typename T>
class KVDBSetHelper : public ::testing::TestWithParam<T>
{
protected:
    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdbManager::IKVDBManager> m_kvdbManager;
    builder::internals::HelperBuilder m_builder;
    std::shared_ptr<defs::mocks::FailDef> m_failDef;
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

        ASSERT_FALSE(m_kvdbManager->createDB("test_db"));

        m_builder = getOpBuilderKVDBSet(m_kvdbManager, "builder_test");
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

using SetParamsT = std::tuple<std::vector<std::string>, bool>;
class SetParams : public KVDBSetHelper<SetParamsT>
{
};

// Test of build params
TEST_P(SetParams, builds)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_set";

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

INSTANTIATE_TEST_SUITE_P(KVDBSet,
                         SetParams,
                         ::testing::Values(
                             // OK
                             SetParamsT({DB_NAME_1, "key", "value"}, true),
                             SetParamsT({DB_NAME_1, "key", ""}, true),
                             // NOK
                             SetParamsT({DB_NAME_1}, false),
                             SetParamsT({DB_NAME_1, "key"}, false),
                             SetParamsT({}, false),
                             SetParamsT({"unknow_database", "key", "value"}, false)));

using SetKeyT = std::tuple<std::vector<std::string>, bool>;
class SetKey : public KVDBSetHelper<SetKeyT>
{
protected:
    void SetUp() override { KVDBSetHelper<SetKeyT>::SetUp(); }
};

// Test of set function
TEST_P(SetKey, setting)
{
    const std::string targetField = "/field";
    const std::string rawName = "kvdb_set";

    auto [parameters, shouldPass] = GetParam();
    auto event = std::make_shared<json::Json>(R"({"result": ""})");
    result::Result<Event> resultEvent;

    if (shouldPass)
    {
        auto op = m_builder(targetField, rawName, parameters, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn();
        ASSERT_NO_THROW(resultEvent = op(event));
        ASSERT_TRUE(resultEvent.success());
        auto value = resultEvent.payload()->getString("/result").value();
        std::cout << "Result: " << value << std::endl;
    }
    else
    {
        ASSERT_THROW (auto op = m_builder(targetField, rawName, parameters, m_failDef)->getPtr<base::Term<base::EngineOp>>()->getFn(), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBSet,
                         SetKey,
                         ::testing::Values(
                             // OK
                             SetKeyT({DB_NAME_1, "key", "value"}, true),
                             SetKeyT({DB_NAME_1, "KEY2", ""}, true),
                             SetKeyT({DB_NAME_1, "", "value"}, true),
                             // NOK
                             SetKeyT({"unknow_database", "key", "value"}, false)));
