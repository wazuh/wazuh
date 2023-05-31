#include <gtest/gtest.h>

#include <any>
#include <memory>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <json/json.hpp>
#include <kvdb2/kvdbManager.hpp>
#include <kvdb2/kvdbExcept.hpp>
#include <opBuilderKVDB.hpp>
#include <testsCommon.hpp>

#include <metrics/metricsManager.hpp>
using namespace metricsManager;

namespace
{
using namespace base;
using namespace builder::internals::builders;

using json::Json;
using std::string;
using std::vector;

class opBuilderKVDBDeleteTest : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME_1 = "TEST_DB_1";
    static constexpr auto DB_NAME_2 = "TEST_DB_2";
    static constexpr auto DB_REF_NAME = "$test_db_name";
    static constexpr auto DB_DIR = "/tmp/";
    static constexpr auto DB_NAME = "kvdb";

    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
    std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope;

    void SetUp() override
    {
        initLogging();

        // cleaning directory in order to start without garbage.
        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }

        m_manager = std::make_shared<MetricsManager>();
        kvdbManager::KVDBManagerOptions kvdbManagerOptions { DB_DIR, DB_NAME };
        kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, m_manager);

        kvdbManager->initialize();

        kvdbScope = kvdbManager->getKVDBScope("builder_test");
        auto err1 = kvdbManager->createDB(DB_NAME_1);
        ASSERT_FALSE(err1);
        auto err2 = kvdbManager->createDB(DB_NAME_2);
        ASSERT_FALSE(err2);
    }

    void TearDown() override
    {
        try
        {
            kvdbManager->finalize();
        }
        catch (kvdbManager::KVDBException& e)
        {
            FAIL() << "KVDBException: " << e.what();
        }

        if (std::filesystem::exists(DB_DIR))
        {
            std::filesystem::remove_all(DB_DIR);
        }
    }
};

// Build ok
TEST_F(opBuilderKVDBDeleteTest, buildKVDBDeleteWithValue)
{
    ASSERT_NO_THROW(KVDBDelete(
        "/output", "", {DB_NAME_1}, std::make_shared<defs::mocks::FailDef>(), opBuilderKVDBDeleteTest::kvdbManager));
}

TEST_F(opBuilderKVDBDeleteTest, buildKVDBDeleteWithReference)
{
    ASSERT_NO_THROW(KVDBDelete(
        "/output", "", {DB_REF_NAME}, std::make_shared<defs::mocks::FailDef>(), opBuilderKVDBDeleteTest::kvdbManager));
}

TEST_F(opBuilderKVDBDeleteTest, buildKVDBDeleteWrongAmountOfParametersError)
{
    ASSERT_THROW(
        KVDBDelete("/output", "", {}, std::make_shared<defs::mocks::FailDef>(), opBuilderKVDBDeleteTest::kvdbManager),
        std::runtime_error);
    ASSERT_THROW(KVDBDelete("/output",
                            "",
                            {DB_REF_NAME, "unexpected_key"},
                            std::make_shared<defs::mocks::FailDef>(),
                            opBuilderKVDBDeleteTest::kvdbManager),
                 std::runtime_error);
    ASSERT_THROW(KVDBDelete("/output",
                            "",
                            {DB_REF_NAME, "unexpected_key", "unexpected_value"},
                            std::make_shared<defs::mocks::FailDef>(),
                            opBuilderKVDBDeleteTest::kvdbManager),
                 std::runtime_error);
}

TEST_F(opBuilderKVDBDeleteTest, DeleteSuccessCases)
{
    auto event = std::make_shared<Json>(R"({})");
    auto expectedEvent = std::make_shared<Json>(R"({})");
    expectedEvent->setBool(true, "/output");

    const auto op1 =
        getOpBuilderKVDBDelete(kvdbManager)("/output", "", {DB_NAME_1}, std::make_shared<defs::mocks::FailDef>());

    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);

    auto eventTemplate = std::string(R"({"test_db_name": ")") + DB_NAME_2 + R"("})";
    event = std::make_shared<Json>(eventTemplate.c_str());
    expectedEvent = std::make_shared<Json>(eventTemplate.c_str());
    expectedEvent->setBool(true, "/output");

    const auto op2 =
        getOpBuilderKVDBDelete(kvdbManager)("/output", "", {DB_REF_NAME}, std::make_shared<defs::mocks::FailDef>());

    result = op2->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);
}

} // namespace