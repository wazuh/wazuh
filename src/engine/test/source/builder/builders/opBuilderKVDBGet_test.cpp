#include <any>
#include <memory>
#include <vector>

#include <gtest/gtest.h>
#include <json/json.hpp>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <kvdb/kvdbManager.hpp>
#include <kvdb/kvdbExcept.hpp>
#include <opBuilderKVDB.hpp>
#include <testsCommon.hpp>

#include <metrics/metricsManager.hpp>
using namespace metricsManager;

namespace
{
using namespace base;
namespace bld = builder::internals::builders;

class opBuilderKVDBGetTest : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME_1 = "TEST_DB";
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
        auto err = kvdbManager->createDB(DB_NAME_1);
        ASSERT_FALSE(std::holds_alternative<base::Error>(err));
        auto result = kvdbScope->getKVDBHandler(DB_NAME_1);
        ASSERT_FALSE(std::holds_alternative<base::Error>(result));
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
TEST_F(opBuilderKVDBGetTest, BuildsGetI)
{
    ASSERT_NO_THROW(bld::KVDBGet("/field",
                                 "",
                                 {DB_NAME_1, "key"},
                                 std::make_shared<defs::mocks::FailDef>(),
                                 false,
                                 opBuilderKVDBGetTest::kvdbScope));
    ASSERT_NO_THROW(bld::KVDBGet("/field",
                                 "",
                                 {DB_NAME_1, "key"},
                                 std::make_shared<defs::mocks::FailDef>(),
                                 true,
                                 opBuilderKVDBGetTest::kvdbScope));
}

TEST_F(opBuilderKVDBGetTest, BuildsGetII)
{
    ASSERT_NO_THROW(bld::KVDBGet("/field",
                                 "",
                                 {DB_NAME_1, "$key"},
                                 std::make_shared<defs::mocks::FailDef>(),
                                 false,
                                 opBuilderKVDBGetTest::kvdbScope));
    ASSERT_NO_THROW(bld::KVDBGet("/field",
                                 "",
                                 {DB_NAME_1, "$key"},
                                 std::make_shared<defs::mocks::FailDef>(),
                                 true,
                                 opBuilderKVDBGetTest::kvdbScope));
}

TEST_F(opBuilderKVDBGetTest, WrongNumberOfParameters)
{
    ASSERT_THROW(bld::KVDBGet("/field",
                              "",
                              {DB_NAME_1},
                              std::make_shared<defs::mocks::FailDef>(),
                              false,
                              opBuilderKVDBGetTest::kvdbScope),
                 std::runtime_error);
    ASSERT_THROW(
        bld::KVDBGet(
            "/field", "", {DB_NAME_1}, std::make_shared<defs::mocks::FailDef>(), true, opBuilderKVDBGetTest::kvdbScope),
        std::runtime_error);
}

TEST_F(opBuilderKVDBGetTest, GetSuccessCases)
{
    // Insert data in DB
    auto res = kvdbScope->getKVDBHandler(DB_NAME_1);
    ASSERT_FALSE(std::holds_alternative<base::Error>(res));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(res));
    handler->set("keyString", R"("string_value")");
    handler->set("keyNumber", "123");
    handler->set("keyObject", R"({"field1": "value1", "field2": "value2"})");
    handler->set("keyArray", R"(["value1", "value2"])");
    handler->set("keyNull", "null");

    // Operations value key
    auto op1 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldString", "", {DB_NAME_1, "keyString"}, std::make_shared<defs::mocks::FailDef>());
    auto op2 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldNumber", "", {DB_NAME_1, "keyNumber"}, std::make_shared<defs::mocks::FailDef>());
    auto op3 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldObject", "", {DB_NAME_1, "keyObject"}, std::make_shared<defs::mocks::FailDef>());
    auto op4 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldArray", "", {DB_NAME_1, "keyArray"}, std::make_shared<defs::mocks::FailDef>());
    auto op5 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldNull", "", {DB_NAME_1, "keyNull"}, std::make_shared<defs::mocks::FailDef>());

    // Operations reference key
    auto op6 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldString", "", {DB_NAME_1, "$keyString"}, std::make_shared<defs::mocks::FailDef>());
    auto op7 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldNumber", "", {DB_NAME_1, "$keyNumber"}, std::make_shared<defs::mocks::FailDef>());
    auto op8 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldObject", "", {DB_NAME_1, "$keyObject"}, std::make_shared<defs::mocks::FailDef>());
    auto op9 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldArray", "", {DB_NAME_1, "$keyArray"}, std::make_shared<defs::mocks::FailDef>());
    auto op10 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/fieldNull", "", {DB_NAME_1, "$keyNull"}, std::make_shared<defs::mocks::FailDef>());

    // Events templates
    json::Json eventTemplate1 {R"({
        "fieldString": "value",
        "fieldNumber": 1,
        "fieldObject": {"field": "value"},
        "fieldArray": ["value"],
        "fieldNull": null,
        "keyString": "keyString",
        "keyNumber": "keyNumber",
        "keyObject": "keyObject",
        "keyArray": "keyArray",
        "keyNull": "keyNull"
    })"};
    json::Json eventTemplate2 {R"({
        "keyString": "keyString",
        "keyNumber": "keyNumber",
        "keyObject": "keyObject",
        "keyArray": "keyArray",
        "keyNull": "keyNull"
    })"};

    // Use case events
    auto event1_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event1_1 = std::make_shared<json::Json>(eventTemplate2);
    auto event2_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event2_1 = std::make_shared<json::Json>(eventTemplate2);
    auto event3_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event3_1 = std::make_shared<json::Json>(eventTemplate2);
    auto event4_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event4_1 = std::make_shared<json::Json>(eventTemplate2);
    auto event5_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event5_1 = std::make_shared<json::Json>(eventTemplate2);
    auto event6_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event6_1 = std::make_shared<json::Json>(eventTemplate2);
    auto event7_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event7_1 = std::make_shared<json::Json>(eventTemplate2);
    auto event8_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event8_1 = std::make_shared<json::Json>(eventTemplate2);
    auto event9_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event9_1 = std::make_shared<json::Json>(eventTemplate2);
    auto event10_0 = std::make_shared<json::Json>(eventTemplate1);
    auto event10_1 = std::make_shared<json::Json>(eventTemplate2);

    // Use case expected events
    auto expectedEvent1_0 = std::make_shared<json::Json>(eventTemplate1);
    expectedEvent1_0->setString("string_value", "/fieldString");
    auto expectedEvent1_1 = std::make_shared<json::Json>(eventTemplate2);
    expectedEvent1_1->setString("string_value", "/fieldString");
    auto expectedEvent2_0 = std::make_shared<json::Json>(eventTemplate1);
    expectedEvent2_0->setInt(123, "/fieldNumber");
    auto expectedEvent2_1 = std::make_shared<json::Json>(eventTemplate2);
    expectedEvent2_1->setInt(123, "/fieldNumber");
    auto expectedEvent3_0 = std::make_shared<json::Json>(eventTemplate1);
    expectedEvent3_0->set("/fieldObject", json::Json {R"({"field1": "value1", "field2": "value2"})"});
    auto expectedEvent3_1 = std::make_shared<json::Json>(eventTemplate2);
    expectedEvent3_1->set("/fieldObject", json::Json {R"({"field1": "value1", "field2": "value2"})"});
    auto expectedEvent4_0 = std::make_shared<json::Json>(eventTemplate1);
    expectedEvent4_0->set("/fieldArray", json::Json {R"(["value1", "value2"])"});
    auto expectedEvent4_1 = std::make_shared<json::Json>(eventTemplate2);
    expectedEvent4_1->set("/fieldArray", json::Json {R"(["value1", "value2"])"});
    auto expectedEvent5_0 = std::make_shared<json::Json>(eventTemplate1);
    expectedEvent5_0->setNull("/fieldNull");
    auto expectedEvent5_1 = std::make_shared<json::Json>(eventTemplate2);
    expectedEvent5_1->setNull("/fieldNull");

    // Use cases string
    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event1_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent1_0);
    result = op1->getPtr<Term<EngineOp>>()->getFn()(event1_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent1_1);
    result = op6->getPtr<Term<EngineOp>>()->getFn()(event6_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent1_0);
    result = op6->getPtr<Term<EngineOp>>()->getFn()(event6_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent1_1);

    // Use cases number
    result = op2->getPtr<Term<EngineOp>>()->getFn()(event2_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent2_0);
    result = op2->getPtr<Term<EngineOp>>()->getFn()(event2_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent2_1);
    result = op7->getPtr<Term<EngineOp>>()->getFn()(event7_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent2_0);
    result = op7->getPtr<Term<EngineOp>>()->getFn()(event7_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent2_1);

    // Use cases object
    result = op3->getPtr<Term<EngineOp>>()->getFn()(event3_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent3_0);
    result = op3->getPtr<Term<EngineOp>>()->getFn()(event3_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent3_1);
    result = op8->getPtr<Term<EngineOp>>()->getFn()(event8_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent3_0);
    result = op8->getPtr<Term<EngineOp>>()->getFn()(event8_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent3_1);

    // Use cases array
    result = op4->getPtr<Term<EngineOp>>()->getFn()(event4_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent4_0);
    result = op4->getPtr<Term<EngineOp>>()->getFn()(event4_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent4_1);
    result = op9->getPtr<Term<EngineOp>>()->getFn()(event9_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent4_0);
    result = op9->getPtr<Term<EngineOp>>()->getFn()(event9_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent4_1);

    // Use cases null
    result = op5->getPtr<Term<EngineOp>>()->getFn()(event5_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent5_0);
    result = op5->getPtr<Term<EngineOp>>()->getFn()(event5_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent5_1);
    result = op10->getPtr<Term<EngineOp>>()->getFn()(event10_0);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent5_0);
    result = op10->getPtr<Term<EngineOp>>()->getFn()(event10_1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent5_1);
}

TEST_F(opBuilderKVDBGetTest, GetFailKeyNotFound)
{
    auto op1 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/field", "", {DB_NAME_1, "NotFoundKey"}, std::make_shared<defs::mocks::FailDef>());
    auto op2 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/field", "", {DB_NAME_1, "$NotFoundKey"}, std::make_shared<defs::mocks::FailDef>());
    auto op3 = bld::getOpBuilderKVDBGet(kvdbScope)(
        "/field", "", {DB_NAME_1, "$fieldNotFound"}, std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({
        "NotFoundKey": "NotFoundKey"
    })");

    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
    result = op2->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
    result = op3->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST_F(opBuilderKVDBGetTest, GetMergeSuccessCases)
{
    // Insert data in DB
    auto res = kvdbScope->getKVDBHandler(DB_NAME_1);
    ASSERT_FALSE(std::holds_alternative<base::Error>(res));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(res));
    handler->set("keyObject", R"({"field1": "value1", "field2": "value2", "field3": "value3"})");
    handler->set("keyArray", R"(["value1", "value2", "value3"])");

    // Operations value key
    auto op1 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/fieldObject", "", {DB_NAME_1, "keyObject"}, std::make_shared<defs::mocks::FailDef>());
    auto op2 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/fieldArray", "", {DB_NAME_1, "keyArray"}, std::make_shared<defs::mocks::FailDef>());

    // Operations reference key
    auto op3 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/fieldObject", "", {DB_NAME_1, "$keyObject"}, std::make_shared<defs::mocks::FailDef>());
    auto op4 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/fieldArray", "", {DB_NAME_1, "$keyArray"}, std::make_shared<defs::mocks::FailDef>());

    // Events templates
    json::Json eventTemplate {R"({
        "fieldObject": {"field2": "value_old"},
        "fieldArray": ["value2"],
        "keyObject": "keyObject",
        "keyArray": "keyArray"
    })"};

    // Use case events
    auto event1 = std::make_shared<json::Json>(eventTemplate);
    auto event2 = std::make_shared<json::Json>(eventTemplate);
    auto event3 = std::make_shared<json::Json>(eventTemplate);
    auto event4 = std::make_shared<json::Json>(eventTemplate);

    // Use case expected events
    auto expectedEvent1 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent1->set("/fieldObject", json::Json {R"({"field2": "value2", "field1": "value1", "field3": "value3"})"});
    auto expectedEvent2 = std::make_shared<json::Json>(eventTemplate);
    expectedEvent2->set("/fieldArray", json::Json {R"(["value2", "value1", "value3"])"});

    // Use cases object
    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event1);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent1);
    result = op3->getPtr<Term<EngineOp>>()->getFn()(event3);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent1);

    // Use cases array
    result = op2->getPtr<Term<EngineOp>>()->getFn()(event2);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent2);
    result = op4->getPtr<Term<EngineOp>>()->getFn()(event4);
    ASSERT_TRUE(result);
    ASSERT_EQ(*result.payload(), *expectedEvent2);
}

TEST_F(opBuilderKVDBGetTest, GetMergeFailKeyNotFound)
{
    auto op1 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/field", "", {DB_NAME_1, "NotFoundKey"}, std::make_shared<defs::mocks::FailDef>());
    auto op2 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/field", "", {DB_NAME_1, "$NotFoundKey"}, std::make_shared<defs::mocks::FailDef>());
    auto op3 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/field", "", {DB_NAME_1, "$fieldNotFound"}, std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({
        "NotFoundKey": "NotFoundKey"
    })");

    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
    result = op2->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
    result = op3->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST_F(opBuilderKVDBGetTest, GetMergeFailTargetNotFound)
{
    // Insert data in DB
    auto res = kvdbScope->getKVDBHandler(DB_NAME_1);
    ASSERT_FALSE(std::holds_alternative<base::Error>(res));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(res));
    handler->set("keyObject", R"({"field1": "value1", "field2": "value2", "field3": "value3"})");

    auto op1 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/fieldNotFound", "", {DB_NAME_1, "keyObject"}, std::make_shared<defs::mocks::FailDef>());
    auto op2 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/fieldNotFound", "", {DB_NAME_1, "$keyObject"}, std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({
        "keyObject": "keyObject"
    })");

    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
    result = op2->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}

TEST_F(opBuilderKVDBGetTest, GetMergeFailTypeErrors)
{
    // Insert data in DB
    auto res = kvdbScope->getKVDBHandler(DB_NAME_1);
    ASSERT_FALSE(std::holds_alternative<base::Error>(res));
    auto handler = std::move(std::get<std::unique_ptr<kvdbManager::IKVDBHandler>>(res));
    handler->set("keyObject", R"({"field1": "value1", "field2": "value2", "field3": "value3"})");
    handler->set("keyArray", R"(["value1", "value2", "value3"])");
    handler->set("keyString", R"("value1")");

    auto op1 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/fieldObject", "", {DB_NAME_1, "keyArray"}, std::make_shared<defs::mocks::FailDef>());
    auto op2 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/fieldArray", "", {DB_NAME_1, "keyObject"}, std::make_shared<defs::mocks::FailDef>());
    auto op3 = bld::getOpBuilderKVDBGetMerge(kvdbScope)(
        "/fieldString", "", {DB_NAME_1, "keyString"}, std::make_shared<defs::mocks::FailDef>());

    auto event = std::make_shared<json::Json>(R"({
        "fieldObject": {"key": "value"},
        "fieldArray": ["value"],
        "fieldString": "value"
    })");

    auto result = op1->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
    result = op2->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
    result = op3->getPtr<Term<EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result);
}
} // namespace
