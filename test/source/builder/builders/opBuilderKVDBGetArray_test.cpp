#include <any>
#include <memory>
#include <vector>

#include <gtest/gtest.h>
#include <json/json.hpp>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <schemf/mockSchema.hpp>

#include <kvdb/kvdbManager.hpp>
#include <opBuilderKVDB.hpp>
#include <testsCommon.hpp>

#include <metrics/metricsManager.hpp>

using namespace metricsManager;

namespace
{
using namespace base;
using namespace builder::internals::builders;

class opBuilderKVDBGetArrayTest : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME_1 = "test_db";
    static constexpr auto DB_DIR = "/tmp/kvdbTestSuitePath/";
    static constexpr auto DB_NAME = "kvdb";

    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
    std::shared_ptr<schemf::ISchema> schema;
    std::string kvdbPath;

    void SetUp() override
    {
        initLogging();

        // cleaning directory in order to start without garbage.
        kvdbPath = generateRandomStringWithPrefix(6, DB_DIR) + "/";

        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }

        m_manager = std::make_shared<MetricsManager>();
        kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, DB_NAME};
        kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, m_manager);
        schema = std::make_shared<schemf::mocks::MockSchema>();

        kvdbManager->initialize();

        ASSERT_FALSE(kvdbManager->createDB("test_db"));
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

template<typename T>
class GetArrayTest : public ::testing::TestWithParam<T>
{

protected:
    static constexpr auto DB_NAME_1 = "test_db";
    static constexpr auto DB_DIR = "/tmp/kvdbTestSuitePath/";
    static constexpr auto DB_NAME = "kvdb";

    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdbManager::KVDBManager> kvdbManager;
    std::shared_ptr<schemf::ISchema> schema;
    std::string kvdbPath;
    builder::internals::HelperBuilder builder;

    void SetUp() override
    {
        initLogging();

        // cleaning directory in order to start without garbage.
        kvdbPath = generateRandomStringWithPrefix(6, DB_DIR) + "/";

        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }

        m_manager = std::make_shared<MetricsManager>();
        kvdbManager::KVDBManagerOptions kvdbManagerOptions {kvdbPath, DB_NAME};
        kvdbManager = std::make_shared<kvdbManager::KVDBManager>(kvdbManagerOptions, m_manager);
        schema = std::make_shared<schemf::mocks::MockSchema>();
        builder = getOpBuilderKVDBGetArray(kvdbManager, DB_NAME_1, schema);

        kvdbManager->initialize();

        ASSERT_FALSE(kvdbManager->createDB("test_db"));
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
} // namespace

// Build ok
TEST_F(opBuilderKVDBGetArrayTest, getBuilder)
{
    ASSERT_NO_THROW(getOpBuilderKVDBGetArray(kvdbManager, DB_NAME_1, schema));
}

using BuildsT = std::tuple<bool, std::string, std::string, std::vector<std::string>>;
using Builds = GetArrayTest<BuildsT>;
TEST_P(Builds, Params)
{
    auto [shouldPass, targetField, name, params] = GetParam();
    auto defs = std::make_shared<defs::mocks::FailDef>();

    if (shouldPass)
    {
        ASSERT_NO_THROW(builder(targetField, name, params, defs));
    }
    else
    {
        ASSERT_THROW(builder(targetField, name, params, defs), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(opBuilderKVDB,
                         Builds,
                         testing::Values(BuildsT(true, "field", "name", {"test_db", "$ref"}),
                                         BuildsT(false, "field", "name", {"test_db"}),
                                         BuildsT(false, "field", "name", {"test_db", "$ref", "extra"}),
                                         BuildsT(false, "field", "name", {"not_exists_db", "$ref"})));

using OperatesT = std::tuple<bool, std::string, std::string, std::vector<std::tuple<std::string, std::string>>>;
using Operates = GetArrayTest<OperatesT>;

TEST_P(Operates, Params)
{
    auto [shouldPass, input, expected, kvdb] = GetParam();
    auto defs = std::make_shared<defs::mocks::FailDef>();
    auto op = builder("/field", "name", {"test_db", "$ref"}, defs)->getPtr<base::Term<base::EngineOp>>()->getFn();

    // Populate kvdb
    auto dbHandler = base::getResponse<std::shared_ptr<kvdbManager::IKVDBHandler>>(
        kvdbManager->getKVDBHandler("test_db", "test_scope"));
    for (auto [key, value] : kvdb)
    {
        ASSERT_FALSE(dbHandler->set(key, value));
    }

    json::Json rawIEvent(input.c_str());
    json::Json oEvent(expected.c_str());

    auto iEvent = std::make_shared<json::Json>(rawIEvent);

    base::result::Result<Event> res;
    ASSERT_NO_THROW(res = op(iEvent));

    if (shouldPass)
    {
        ASSERT_TRUE(res.success()) << res.trace();
        ASSERT_EQ(*(res.payload()), oEvent);
    }
    else
    {
        ASSERT_TRUE(res.failure());
    }
}

INSTANTIATE_TEST_SUITE_P(
    opBuilderKVDB,
    Operates,
    testing::Values(
        OperatesT(true, R"({"ref": ["key"]})", R"({"ref": ["key"], "field":["value"]})", {{"key", R"("value")"}}),
        OperatesT(true,
                  R"({"ref": ["key1", "key2"]})",
                  R"({"ref": ["key1", "key2"], "field":[1, 2]})",
                  {{"key1", R"(1)"}, {"key2", R"(2)"}}),
        OperatesT(true,
                  R"({"ref": ["key1", "key2", "key3"]})",
                  R"({"ref": ["key1", "key2", "key3"], "field":["1", "2"]})",
                  {{"key1", R"("1")"}, {"key2", R"("2")"}}),
        OperatesT(false, "{}", "{}", {}),
        OperatesT(false, R"({"ref": [1]})", R"({"ref": [1]})", {{"key1", R"("1")"}, {"key2", R"("2")"}}),
        OperatesT(false, R"({"ref": []})", R"({"ref": []})", {{"key1", R"("1")"}, {"key2", R"("2")"}}),
        OperatesT(false, R"({"ref": ["key"]})", R"({"ref": ["key"]})", {{"key1", R"("1")"}, {"key2", R"("2")"}}),
        OperatesT(false,
                  R"({"ref": ["key1", "key2"]})",
                  R"({"ref": ["key1", "key2"]})",
                  {{"key1", R"(1)"}, {"key2", R"("2")"}}),
        OperatesT(false,
                  R"({"other": ["key1", "key2"]})",
                  R"({"other": ["key1", "key2"]})",
                  {{"key1", R"(1)"}, {"key2", R"(2)"}})));
