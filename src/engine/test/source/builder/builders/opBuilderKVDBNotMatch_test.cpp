#include <vector>

#include <gtest/gtest.h>

#include "opBuilderKVDB.hpp"
#include <defs/mocks/failDef.hpp>
#include <rapidjson/document.h>
#include <kvdb2/kvdbManager.hpp>
#include <kvdb2/kvdbExcept.hpp>
#include <metrics/metricsManager.hpp>

using namespace metricsManager;

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

namespace
{
class opBuilderKVDBNotMatchTest : public ::testing::Test
{

protected:
    static constexpr auto DB_DIR = "/tmp/";
    static constexpr auto DB_NAME = "kvdb";
    static constexpr auto DB_NAME_1 = "TEST_DB";

    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
    std::shared_ptr<kvdbManager::IKVDBScope> kvdbScope;

    void SetUp() override
    {
        m_manager = std::make_shared<MetricsManager>();
        kvdbManager::KVDBManagerOptions kvdbManagerOptions { DB_DIR, DB_NAME };
        kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, m_manager);

        kvdbScope = kvdbManager->getKVDBScope("builder_test");
        auto err = kvdbManager->createDB(DB_NAME_1);
        ASSERT_FALSE(err);
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
TEST_F(opBuilderKVDBNotMatchTest, Builds)
{
    Document doc {R"({
        "check":
            {"field2match": "+kvdb_not_match/TEST_DB"}
    })"};
    ASSERT_NO_THROW(bld::opBuilderKVDBNotMatch(doc.get("/check"), tr, std::make_shared<defs::mocks::FailDef>()));
}

// Build incorrect number of arguments
TEST_F(opBuilderKVDBNotMatchTest, Builds_incorrect_number_of_arguments)
{
    Document doc {R"({
        "check":
            {"field2match": "+kvdb_not_match"}
    })"};
    ASSERT_THROW(bld::opBuilderKVDBNotMatch(doc.get("/check"), tr, std::make_shared<defs::mocks::FailDef>()),
                 std::runtime_error);
}

// Build invalid DB
TEST_F(opBuilderKVDBNotMatchTest, Builds_incorrect_invalid_db)
{
    Document doc {R"({
        "check":
            {"field2match": "+kvdb_not_match/INVALID_DB"}
    })"};
    ASSERT_THROW(bld::opBuilderKVDBNotMatch(doc.get("/check"), tr, std::make_shared<defs::mocks::FailDef>()),
                 std::runtime_error);
}

// Test ok: static values
TEST_F(opBuilderKVDBNotMatchTest, Static_string_ok)
{
    // Set Up KVDB
    auto res = kvdbManager->getHandler("TEST_DB");
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);
    kvdb->writeKeyOnly("KEY");

    Document doc {R"({
        "check":
            {"field2match": "+kvdb_match/TEST_DB"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field2match":"KEY"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field2match":"INEXISTENT_KEY"}
            )"));
            // Other fields will be ignored
            s.on_next(createSharedEvent(R"(
                {"otherfield":"KEY"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderKVDBNotMatch(doc.get("/check"), tr, std::make_shared<defs::mocks::FailDef>());
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->getEvent()->get("/field2match").GetString(), "INEXISTENT_KEY");
    ASSERT_STREQ(expected[1]->getEvent()->get("/otherfield").GetString(), "KEY");
}

TEST_F(opBuilderKVDBNotMatchTest, Multilevel_target)
{
    auto res = kvdbManager->getHandler("TEST_DB");
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);
    kvdb->writeKeyOnly("KEY");

    Document doc {R"({
        "check":
            {"a.b.field2match": "+kvdb_not_match/TEST_DB"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"a": {"b":{"field2match":"KEY"}}}
            )"));
            s.on_next(createSharedEvent(R"(
                {"a": {"b":{"field2match":"INEXISTENT_KEY"}}}
            )"));
            // Other fields will continue
            s.on_next(createSharedEvent(R"(
                {"a": {"b":{"otherfield":"KEY"}}}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderKVDBNotMatch(doc.get("/check"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    ASSERT_EQ(expected.size(), 2);
    ASSERT_STREQ(expected[0]->getEvent()->get("/a/b/field2match").GetString(), "INEXISTENT_KEY");
    ASSERT_STREQ(expected[1]->getEvent()->get("/a/b/otherfield").GetString(), "KEY");
}

} // namespace