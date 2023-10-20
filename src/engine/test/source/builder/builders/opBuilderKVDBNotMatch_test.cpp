#include <vector>

#include <gtest/gtest.h>

#include "opBuilderKVDB.hpp"
#include <defs/mocks/failDef.hpp>
#include <kvdb/ikvdbmanager.hpp>
#include <kvdb/kvdbManager.hpp>
#include <logging/logging.hpp>
#include <metrics/metricsManager.hpp>
#include <rapidjson/document.h>

using namespace metricsManager;

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

namespace
{

const std::string KVDB_PATH {"/tmp/kvdb_test/"};
const std::string KVDB_DB_FILENAME {"TEST_DB"};

std::filesystem::path uniquePath(const std::string& path)
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid << "/"; // Unique path per thread and process
    return std::filesystem::path(path) / ss.str();
}

class opBuilderKVDBNotMatchTest : public ::testing::Test
{
protected:
    std::shared_ptr<IMetricsManager> m_metricsManager;
    std::shared_ptr<kvdbManager::IKVDBManager> m_kvdbManager;
    std::string kvdbPath;

    void SetUp() override
    {
        logging::testInit();

        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }

        m_metricsManager = std::make_shared<MetricsManager>();
        kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, KVDB_DB_FILENAME};
        m_kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, m_metricsManager);
    }

    void TearDown() override
    {
        try
        {
            kvdbManager->finalize();
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

// Build ok
TEST_F(opBuilderKVDBNotMatchTest, Builds)
{
    rapidjson::Document doc {R"({
        "check":
            {"field2match": "+kvdb_not_match/TEST_DB"}
    })"};
    ASSERT_NO_THROW(bld::opBuilderKVDBNotMatch(doc.get("/check"), tr, std::make_shared<defs::mocks::FailDef>()));
}

// Build incorrect number of arguments
TEST_F(opBuilderKVDBNotMatchTest, Builds_incorrect_number_of_arguments)
{
    rapidjson::Document doc {R"({
        "check":
            {"field2match": "+kvdb_not_match"}
    })"};
    ASSERT_THROW(bld::opBuilderKVDBNotMatch(doc.get("/check"), tr, std::make_shared<defs::mocks::FailDef>()),
                 std::runtime_error);
}

// Build invalid DB
TEST_F(opBuilderKVDBNotMatchTest, Builds_incorrect_invalid_db)
{
    rapidjson::Document doc {R"({
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
    auto res = kvdbManager->getHandler("TEST_DB", "builder_test");
    if (auto err = std::get_if<base::Error>(&res))
    {
        throw std::runtime_error(err->message);
    }
    auto kvdb = std::get<kvdb_manager::KVDBHandle>(res);
    kvdb->writeKeyOnly("KEY");

    rapidjson::Document doc {R"({
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

    rapidjson::Document doc {R"({
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
