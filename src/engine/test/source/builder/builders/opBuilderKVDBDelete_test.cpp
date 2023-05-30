/*
#include <gtest/gtest.h>

#include <any>
#include <memory>
#include <vector>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <json/json.hpp>
#include <kvdb/kvdbManager.hpp>
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

    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdb_manager::KVDBManager> kvdbManager;

    void SetUp() override
    {
        initLogging();
        m_manager = std::make_shared<MetricsManager>();
        kvdbManager = std::make_shared<kvdb_manager::KVDBManager>(opBuilderKVDBDeleteTest::DB_DIR, m_manager);
    }

    void TearDown() override {}
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

    {
        auto res = kvdbManager->getHandler(DB_NAME_1, true);
        ASSERT_FALSE(std::holds_alternative<base::Error>(res));
    }

    const auto op1 =
        getOpBuilderKVDBDelete(kvdbManager)("/output", "", {DB_NAME_1}, std::make_shared<defs::mocks::FailDef>());

    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);

    {
        auto res = kvdbManager->getHandler(DB_NAME_1, false);
        ASSERT_TRUE(std::holds_alternative<base::Error>(res));
    }

    auto eventTemplate = std::string(R"({"test_db_name": ")") + DB_NAME_2 + R"("})";
    event = std::make_shared<Json>(eventTemplate.c_str());
    expectedEvent = std::make_shared<Json>(eventTemplate.c_str());
    expectedEvent->setBool(true, "/output");

    {
        auto res = kvdbManager->getHandler(DB_NAME_2, true);
        ASSERT_FALSE(std::holds_alternative<base::Error>(res));
    }

    const auto op2 =
        getOpBuilderKVDBDelete(kvdbManager)("/output", "", {DB_REF_NAME}, std::make_shared<defs::mocks::FailDef>());

    result = op2->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent);

    {
        auto res = kvdbManager->getHandler(DB_NAME_2, false);
        ASSERT_TRUE(std::holds_alternative<base::Error>(res));
    }
}

} // namespace
*/