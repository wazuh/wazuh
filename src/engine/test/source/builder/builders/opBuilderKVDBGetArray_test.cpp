#include <any>
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

static constexpr auto DB_NAME_1 = "test_db";

class KVDBGetArray : public ::testing::Test
{
protected:
    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager;
    std::shared_ptr<schemf::mocks::MockSchema> m_schema;
    builder::internals::HelperBuilder builder;

    void SetUp() override
    {
        logging::testInit();

        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
        m_manager = std::make_shared<FakeMetricManager>();
        m_schema = std::make_shared<schemf::mocks::MockSchema>();

        EXPECT_CALL(*m_schema, hasField(testing::_)).WillRepeatedly(testing::Return(false));
        builder = getOpBuilderKVDBGetArray(m_kvdbManager, "builder_test", m_schema);
    }

    void TearDown() override {}
};

template<typename T>
class GetArrayTest : public ::testing::TestWithParam<T>
{

protected:
    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager;
    std::shared_ptr<schemf::mocks::MockSchema> m_schema;
    builder::internals::HelperBuilder builder;

    void SetUp() override
    {
        logging::testInit();

        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
        m_manager = std::make_shared<FakeMetricManager>();
        m_schema = std::make_shared<schemf::mocks::MockSchema>();

        EXPECT_CALL(*m_schema, hasField(testing::_)).WillRepeatedly(testing::Return(false));
        builder = getOpBuilderKVDBGetArray(m_kvdbManager, "builder_test", m_schema);
    }

    void TearDown() override {}
};
} // namespace

// Build ok
TEST_F(KVDBGetArray, builder)
{
    ASSERT_NO_THROW(getOpBuilderKVDBGetArray(m_kvdbManager, "builder_test", m_schema));
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

// Default expected function
template<typename Ret = base::OptError>
using ExpectedFn =
    std::function<Ret(std::shared_ptr<kvdb::mocks::MockKVDBManager>, std::shared_ptr<kvdb::mocks::MockKVDBHandler>)>;
using Behaviour =
    std::function<void(std::shared_ptr<kvdb::mocks::MockKVDBManager>, std::shared_ptr<kvdb::mocks::MockKVDBHandler>)>;

ExpectedFn<> success(Behaviour behaviour = nullptr)
{
    return [behaviour](auto manager, auto handler)
    {
        if (behaviour)
        {
            behaviour(manager, handler);
        }
        return base::noError();
    };
}
ExpectedFn<> failure(Behaviour behaviour = nullptr)
{
    return [behaviour](auto manager, auto handler)
    {
        if (behaviour)
        {
            behaviour(manager, handler);
        }
        return base::Error {};
    };
}

template<typename Ret>
using BehaviourRet = std::function<base::RespOrError<Ret>(std::shared_ptr<kvdb::mocks::MockKVDBManager>,
                                                          std::shared_ptr<kvdb::mocks::MockKVDBHandler>)>;

template<typename Ret>
ExpectedFn<base::RespOrError<Ret>> success(BehaviourRet<Ret> behaviour = nullptr)
{
    return [behaviour](auto store, auto validator) -> base::RespOrError<Ret>
    {
        if (behaviour)
        {
            return behaviour(store, validator);
        }

        return Ret {};
    };
}

template<typename Ret>
ExpectedFn<base::RespOrError<Ret>> failure(Behaviour behaviour = nullptr)
{
    return [behaviour](auto store, auto validator)
    {
        if (behaviour)
        {
            behaviour(store, validator);
        }
        return base::Error {};
    };
}

using OperatesT = std::tuple<std::string, ExpectedFn<base::RespOrError<std::string>>>;
using Operates = GetArrayTest<OperatesT>;

TEST_P(Operates, params)
{
    auto [rawEvent, expectedFn] = GetParam();
    auto defs = std::make_shared<defs::mocks::FailDef>();
    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    auto expected = expectedFn(m_kvdbManager, kvdbHandler);

    auto op = builder("/field", "name", {"test_db", "$ref"}, defs)->getPtr<base::Term<base::EngineOp>>()->getFn();

    json::Json event(rawEvent.c_str());

    auto iEvent = std::make_shared<json::Json>(event);

    base::result::Result<Event> res;
    ASSERT_NO_THROW(res = op(iEvent));

    if (base::isError(expected))
    {
        ASSERT_TRUE(res.failure());
    }
    else
    {
        json::Json expectedEvent(base::getResponse<std::string>(expected).c_str());
        ASSERT_TRUE(res.success()) << res.trace();
        ASSERT_EQ(*(res.payload()), expectedEvent);
    }
}

INSTANTIATE_TEST_SUITE_P(
    KVDBGetArray,
    Operates,
    testing::Values(
        OperatesT(
            R"({"ref": ["key"]})",
            success<std::string>(
                [](auto manager, auto handler)
                {
                    EXPECT_CALL(*manager, getKVDBHandler("test_db", "builder_test")).WillOnce(testing::Return(handler));
                    EXPECT_CALL(*handler, get("key")).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(R"("value")")));
                    return R"({"ref": ["key"], "field":["value"]})";
                })),
        OperatesT(R"({"ref": ["key1", "key2"]})",
                  success<std::string>(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler("test_db", "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("key1")).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(R"(1)")));
                          EXPECT_CALL(*handler, get("key2")).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(R"(2)")));
                          return R"({"ref": ["key1", "key2"], "field":[1, 2]})";
                      })),
        OperatesT(R"({"ref": ["key1", "key2", "key3"]})",
                  success<std::string>(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler("test_db", "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("key1")).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(R"("")")));
                          EXPECT_CALL(*handler, get("key2")).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(R"("")")));
                          EXPECT_CALL(*handler, get("key3")).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(R"("")")));
                          return R"({"ref": ["key1", "key2", "key3"],"field":["","",""]})";
                      })),
        OperatesT(R"({})",
                  failure<std::string>(
                      [](auto manager, auto handler) {
                          EXPECT_CALL(*manager, getKVDBHandler("test_db", "builder_test"))
                              .WillOnce(testing::Return(handler));
                      })),
        OperatesT(R"({"ref": [1]})",
                  failure<std::string>(
                      [](auto manager, auto handler) {
                          EXPECT_CALL(*manager, getKVDBHandler("test_db", "builder_test"))
                              .WillOnce(testing::Return(handler));
                      })),
        OperatesT(R"({"ref": []})",
                  failure<std::string>(
                      [](auto manager, auto handler) {
                          EXPECT_CALL(*manager, getKVDBHandler("test_db", "builder_test"))
                              .WillOnce(testing::Return(handler));
                      })),
        OperatesT(R"({"other": ["key1", "key2"]})",
                  failure<std::string>(
                      [](auto manager, auto handler) {
                          EXPECT_CALL(*manager, getKVDBHandler("test_db", "builder_test"))
                              .WillOnce(testing::Return(handler));
                      }))));
