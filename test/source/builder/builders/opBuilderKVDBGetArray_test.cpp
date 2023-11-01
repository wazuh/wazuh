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
#include <logging/logging.hpp>
#include <mocks/fakeMetric.hpp>
#include <opBuilderKVDB.hpp>
#include <schemf/mockSchema.hpp>

namespace
{
using namespace base;
using namespace metricsManager;
using namespace builder::internals::builders;

std::filesystem::path uniquePath()
{
    auto pid = getpid();
    auto tid = std::this_thread::get_id();
    std::stringstream ss;
    ss << pid << "_" << tid; // Unique path per thread and process
    return std::filesystem::path("/tmp") / (ss.str() + "_kvdbTestSuitePath/");
}

class KVDBGetArray : public ::testing::Test
{

protected:
    static constexpr auto DB_NAME_1 = "test_db";
    static constexpr auto DB_DIR = "/tmp/kvdbTestSuitePath/";
    static constexpr auto DB_NAME = "kvdb";

    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager;
    std::shared_ptr<schemf::ISchema> schema;
    builder::internals::HelperBuilder builder;
    std::string kvdbPath;

    void SetUp() override
    {
        logging::testInit();

        // cleaning directory in order to start without garbage.
        kvdbPath = uniquePath().string();

        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }

        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
        m_manager = std::make_shared<FakeMetricManager>();
        schema = std::make_shared<schemf::mocks::MockSchema>();

        builder = getOpBuilderKVDBGetArray(m_kvdbManager, "builder_test", schema);
    }

    void TearDown() override
    {
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
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager;
    std::shared_ptr<schemf::ISchema> schema;
    builder::internals::HelperBuilder builder;
    std::string kvdbPath;

    void SetUp() override
    {
        logging::testInit();

        // cleaning directory in order to start without garbage.
        kvdbPath = uniquePath().string();

        if (std::filesystem::exists(kvdbPath))
        {
            std::filesystem::remove_all(kvdbPath);
        }

        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
        m_manager = std::make_shared<FakeMetricManager>();
        schema = std::make_shared<schemf::mocks::MockSchema>();

        builder = getOpBuilderKVDBGetArray(m_kvdbManager, "builder_test", schema);
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

// Build ok
TEST_F(KVDBGetArray, builder)
{
    ASSERT_NO_THROW(getOpBuilderKVDBGetArray(m_kvdbManager, "builder_test", schema));
}

// Database not exists
TEST_F(KVDBGetArray, databaseNotExists)
{
    std::vector<std::string> params;

    params.emplace_back("not_exists_db");
    params.emplace_back("$key");

    auto defs = std::make_shared<defs::mocks::FailDef>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler("not_exists_db", "builder_test"))
        .WillOnce(testing::Return(kvdb::mocks::kvdbGetKVDBHandlerError("")));
    ASSERT_THROW(builder("field", "name", params, defs), std::runtime_error);
}

using BuildsT = std::tuple<bool, std::string, std::string, std::vector<std::string>>;
using Builds = GetArrayTest<BuildsT>;
TEST_P(Builds, params)
{
    auto [shouldPass, targetField, name, params] = GetParam();
    auto defs = std::make_shared<defs::mocks::FailDef>();
    if (shouldPass)
    {
        auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
        EXPECT_CALL(*m_kvdbManager, getKVDBHandler(DB_NAME_1, "builder_test")).WillOnce(testing::Return(kvdbHandler));
        ASSERT_NO_THROW(builder(targetField, name, params, defs));
    }
    else
    {
        ASSERT_THROW(builder(targetField, name, params, defs), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(KVDBGetArray,
                         Builds,
                         testing::Values(BuildsT(true, "field", "name", {"test_db", "$ref"}),
                                         BuildsT(false, "field", "name", {"test_db"}),
                                         BuildsT(false, "field", "name", {"test_db", "$ref", "extra"})));

using OperatesT = std::tuple<bool, std::string, std::string>;
using Operates = GetArrayTest<OperatesT>;

TEST_P(Operates, params)
{
    auto [shouldPass, event, expected] = GetParam();
    auto defs = std::make_shared<defs::mocks::FailDef>();
    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler("test_db", "builder_test")).WillOnce(testing::Return(kvdbHandler));
    auto op = builder("/field", "name", {"test_db", "$ref"}, defs)->getPtr<base::Term<base::EngineOp>>()->getFn();

    json::Json rawIEvent(event.c_str());
    json::Json oEvent(expected.c_str());

    auto iEvent = std::make_shared<json::Json>(rawIEvent);

    base::result::Result<Event> res;
    EXPECT_CALL(*kvdbHandler, get(testing::_)).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk()));
    ASSERT_NO_THROW(res = op(iEvent));

    if (shouldPass)
    {
        ASSERT_TRUE(res.success()) << res.trace();
    }
    else
    {
        ASSERT_TRUE(res.failure());
    }

    ASSERT_EQ(*(res.payload()), oEvent);
}

// TODO: implement lambda

INSTANTIATE_TEST_SUITE_P(
    KVDBGetArray,
    Operates,
    testing::Values(OperatesT(true, R"({"ref": ["key"]})", R"({"ref": ["key"], "field":["value"]})")));

/*INSTANTIATE_TEST_SUITE_P(
    KVDBGetArray,
    Operates,
    testing::Values(OperatesT(true, R"({"ref": ["key"]})", R"({"ref": ["key"], "field":["value"]})"),
                    OperatesT(true, R"({"ref": ["key1", "key2"]})", R"({"ref": ["key1", "key2"], "field":[1, 2]})"),
                    OperatesT(true, R"({"ref": ["key1", "key2", "key3"]})", R"({"ref": ["key1", "key2", "key3"]})"),
                    OperatesT(false, "{}", "{}"),
                    OperatesT(false, R"({"ref": [1]})", R"({"ref": [1]})"),
                    OperatesT(false, R"({"ref": []})", R"({"ref": []})"),
                    OperatesT(false, R"({"ref": ["key"]})", R"({"ref": ["key"]})"),
                    OperatesT(false, R"({"ref": ["key1", "key2"]})", R"({"ref": ["key1", "key2"]})"),
                    OperatesT(false, R"({"other": ["key1", "key2"]})", R"({"other": ["key1", "key2"]})")));
*/
