#include <any>
#include <memory>
#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>
#include <defs/mocks/failDef.hpp>
#include <json/json.hpp>
#include <kvdb/mockKvdbHandler.hpp>
#include <kvdb/mockKvdbManager.hpp>
#include <logging/logging.hpp>
#include <metrics/metricsManager.hpp>
#include <schemf/mockSchema.hpp>
#include <windowsHelper.hpp>

using namespace metricsManager;

namespace
{
using namespace base;
using namespace builder::internals::builders;

constexpr auto DB_NAME_1 = "test_db";

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

template<typename T>
class WindowsHelper : public ::testing::TestWithParam<T>
{
protected:
    std::shared_ptr<IMetricsManager> m_manager;
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager;
    std::shared_ptr<schemf::mocks::MockSchema> m_schema;
    std::shared_ptr<defs::mocks::FailDef> m_failDef;
    builder::internals::HelperBuilder m_builder;

    void SetUp() override
    {
        logging::testInit();

        m_manager = std::make_shared<MetricsManager>();
        m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
        m_schema = std::make_shared<schemf::mocks::MockSchema>();
        EXPECT_CALL(*m_schema, hasField(testing::_)).WillRepeatedly(testing::Return(false));

        m_failDef = std::make_shared<defs::mocks::FailDef>();

        m_builder = getWindowsSidListDescHelperBuilder(m_kvdbManager, "builder_test", m_schema);
    }

    void TearDown() override {}
};
} // namespace

class MakeInitialState
{
public:
    json::Json m_json;

    MakeInitialState() { m_json = json::Json {R"( {} )"}; }

    MakeInitialState& setASD(const std::string& jVal)
    {

        json::Json val {jVal.c_str()};
        m_json.set("/accountSIDDescription", val);
        return *this;
    }

    MakeInitialState& setDSS(const std::string& jVal)
    {

        json::Json val {jVal.c_str()};
        m_json.set("/domainSpecificSID", val);
        return *this;
    }

    // cast to json::Json
    operator json::Json() const { return m_json; }
};

const std::string VALID_ASD = R"( {"S-1-5-32-544": "Administrators",
                                   "S-1-5-32-545": "Users",
                                   "S-1-5-32-546": "Guests",
                                   "S-1-5-32-547": "Power Users"} )";
const std::string VALID_DSS = R"( { "498": "Enterprise Read-only Domain Controllers",
                                    "500": "Administrator",
                                    "501": "Guest",
                                    "512": "Domain Admins"} )";

// Test of build map from DB
using BuildMapT = std::tuple<json::Json, ExpectedFn<>>;
class WindowsBuildMaps : public WindowsHelper<BuildMapT>
{
};

TEST_P(WindowsBuildMaps, builds)
{
    const std::string dstFild = "dstField";
    const std::string srcFild = "$sidList";

    auto [initialState, expectedFn] = GetParam();
    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();

    auto expected = expectedFn(m_kvdbManager, kvdbHandler);

    if (base::isError(expected))
    {
        ASSERT_THROW(m_builder(dstFild, "name", {DB_NAME_1, srcFild}, m_failDef), std::runtime_error);
    }
    else
    {
        ASSERT_NO_THROW(m_builder(dstFild, "name", {DB_NAME_1, srcFild}, m_failDef));
    }
}

INSTANTIATE_TEST_SUITE_P(
    WindowsSidDesc,
    WindowsBuildMaps,
    ::testing::Values(
        // Ok map
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(VALID_DSS),
                  success(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));
                      })),
        // Empty map
        BuildMapT(MakeInitialState(),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        // Empty accountSIDDescription
        BuildMapT(MakeInitialState().setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        // Empty domainSpecificSID
        BuildMapT(MakeInitialState().setASD(VALID_ASD),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        // Empty accountSIDDescription and domainSpecificSID
        BuildMapT(MakeInitialState().setASD(R"( {} )").setDSS(R"( {} )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        // invalid types of accountSIDDescription
        BuildMapT(MakeInitialState().setASD(R"( null )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(R"( 123 )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                          ;
                      })),
        BuildMapT(MakeInitialState().setASD(R"( "asd" )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(R"( false )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(R"( ["null"] )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(R"( [{"key": "value"}] )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        // invalid types of domainSpecificSID
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( null )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( 123 )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( "asd" )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( false )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( ["null"] )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( [{"key": "value"}] )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        // Value of accountSIDDescription is not string
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": null} )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": 123} )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": false} )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": ["null"]} )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": [{"key": "value"}]} )").setDSS(VALID_DSS),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        // Value of domainSpecificSID is not string
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": null} )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": 123} )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": false} )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": ["null"]} )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      })),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": [{"key": "value"}]} )"),
                  failure(
                      [](auto manager, auto handler)
                      {
                          EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                              .WillOnce(testing::Return(handler));
                          EXPECT_CALL(*handler, get("accountSIDDescription"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                          EXPECT_CALL(*handler, get("domainSpecificSID"))
                              .WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
                      }))
        // end
        ));

// Test of search map in DB [mask value, expected array result, should pass]
using WindowsBuildParamsT = std::tuple<std::vector<std::string>, bool>;
class WindowsBuildParams : public WindowsHelper<WindowsBuildParamsT>
{
};

TEST_P(WindowsBuildParams, build)
{
    const std::string dstFieldPath = "/dstField";

    auto [params, shouldPass] = GetParam();

    if (shouldPass)
    {
        auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
        EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test")).WillOnce(testing::Return(kvdbHandler));
        EXPECT_CALL(*kvdbHandler, get("accountSIDDescription"))
            .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
        EXPECT_CALL(*kvdbHandler, get("domainSpecificSID"))
            .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));
        ASSERT_NO_THROW(m_builder(dstFieldPath, "name", params, m_failDef));
    }
    else
    {
        ASSERT_THROW(m_builder(dstFieldPath, "name", params, m_failDef), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(WindowsSidDesc,
                         WindowsBuildParams,
                         ::testing::Values(
                             // Ok params aand map
                             WindowsBuildParamsT({DB_NAME_1, "$ref"}, true),
                             // bad size
                             WindowsBuildParamsT({DB_NAME_1}, false),
                             WindowsBuildParamsT({DB_NAME_1, "$ref", "$ref"}, false),
                             // bad type
                             WindowsBuildParamsT({DB_NAME_1, "notRef"}, false),
                             WindowsBuildParamsT({"$ref", "notRef"}, false)
                             // end
                             ));

// Test of unknow DB
class WindowsSidDesc : public testing::Test
{
protected:
    std::shared_ptr<kvdb::mocks::MockKVDBManager> m_kvdbManager = std::make_shared<kvdb::mocks::MockKVDBManager>();
    std::shared_ptr<schemf::mocks::MockSchema> m_schema = std::make_shared<schemf::mocks::MockSchema>();
    std::shared_ptr<defs::mocks::FailDef> m_failDef = std::make_shared<defs::mocks::FailDef>();
    builder::internals::HelperBuilder m_builder =
        getWindowsSidListDescHelperBuilder(m_kvdbManager, "builder_test", m_schema);
};

TEST_F(WindowsSidDesc, UnknowDatabase)
{
    const std::string dstFieldPath = "/dstField";
    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    std::vector<std::string> params;

    params.emplace_back("not_exists_db");
    params.emplace_back("$key");

    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(params[0], "builder_test")).WillOnce(testing::Return(kvdbHandler));
    ASSERT_THROW(m_builder(dstFieldPath, "name", params, m_failDef), std::runtime_error);
}

// Test of get description from DB [reference source json value, expected description (if is not empty then should
// pass)]
using WindowsSidDescExecT = std::tuple<std::string, ExpectedFn<base::RespOrError<std::vector<std::string>>>>;
class WindowsSidDescExec : public WindowsHelper<WindowsSidDescExecT>
{
};

TEST_P(WindowsSidDescExec, exec)
{

    auto [listStrValue, expectedFn] = GetParam();
    std::vector<json::Json> expectedArray {};

    const std::string dstFieldPath = "/dstField";
    const std::string srcListPath = "/winList";
    const std::string srcListRef = "$winList";

    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();

    auto expected = expectedFn(m_kvdbManager, kvdbHandler);

    auto op = m_builder(dstFieldPath, "name", {DB_NAME_1, srcListRef}, m_failDef)
                  ->getPtr<base::Term<base::EngineOp>>()
                  ->getFn();

    // build event
    auto event = std::make_shared<json::Json>(R"({})");
    if (!listStrValue.empty())
    {
        event->set(srcListPath, json::Json {listStrValue.c_str()});
    }

    result::Result<Event> res;
    ASSERT_NO_THROW(res = op(event));

    if (base::isError(expected))
    {
        ASSERT_TRUE(res.failure());
    }
    else
    {
        auto expectedArrayStr = base::getResponse<std::vector<std::string>>(expected);

        for (auto& str : expectedArrayStr)
        {
            json::Json item {};
            item.setString(str);
            expectedArray.push_back(std::move(item));
        }
        ASSERT_TRUE(res.success());
        auto jArray = res.payload()->getArray(dstFieldPath);
        ASSERT_TRUE(jArray.has_value());
        ASSERT_EQ(jArray.value().size(), expectedArray.size());
        for (size_t i = 0; i < expectedArray.size(); ++i)
        {
            ASSERT_EQ(jArray.value()[i], expectedArray[i]);
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    WindowsSidDesc,
    WindowsSidDescExec,
    ::testing::Values(
        // Single result
        WindowsSidDescExecT(R"( "%{S-1-5-32-544}" )",
                            success<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));

                                    return std::vector<std::string> {"Administrators"};
                                })),
        WindowsSidDescExecT(R"( "%{S-1-5-32-545}" )",
                            success<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));

                                    return std::vector<std::string> {"Users"};
                                })),
        WindowsSidDescExecT(R"( "%{S-1-5-32-546}" )",
                            success<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));

                                    return std::vector<std::string> {"Guests"};
                                })),
        WindowsSidDescExecT(R"( "%{S-1-5-32-547}" )",
                            success<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));

                                    return std::vector<std::string> {"Power Users"};
                                })),
        WindowsSidDescExecT(R"( "%{S-1-5-32-123-54-65}" )",
                            success<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));

                                    return std::vector<std::string> {"S-1-5-32-123-54-65"};
                                })),
        // Start with S-1-5-21 and end with numbers
        // https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#sids-added-by-windows-server-2012-and-later-versions
        WindowsSidDescExecT(R"( "%{S-1-5-21-1004336348-1177238915-682003330-512}" )",
                            success<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));

                                    return std::vector<std::string> {"Domain Admins"};
                                })),
        // Match 5-11-21 and end with numbers (not valid)
        WindowsSidDescExecT(R"( "%{S-1-5-21-1004336348-1177238915-682003330-4000}" )",
                            success<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));

                                    return std::vector<std::string> {"S-1-5-21-1004336348-1177238915-682003330-4000"};
                                })),
        // TODO Check multiple sids
        WindowsSidDescExecT(R"( "%{S-1-5-32-544} %{S-1-5-32-123-54-65}" )",
                            success<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));

                                    return std::vector<std::string> {"Administrators", "S-1-5-32-123-54-65"};
                                })),
        // Unexpected values
        WindowsSidDescExecT("",
                            failure<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));
                                })),
        WindowsSidDescExecT(R"( null )",
                            failure<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));
                                })),
        WindowsSidDescExecT(R"( 123 )",
                            failure<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));
                                })),
        WindowsSidDescExecT(R"( false )",
                            failure<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));
                                })),
        WindowsSidDescExecT(R"( ["null"] )",
                            failure<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));
                                })),
        WindowsSidDescExecT(R"( [{"key": "value"}] )",
                            failure<std::vector<std::string>>(
                                [](auto manager, auto handler)
                                {
                                    EXPECT_CALL(*manager, getKVDBHandler(DB_NAME_1, "builder_test"))
                                        .WillOnce(testing::Return(handler));
                                    EXPECT_CALL(*handler, get("accountSIDDescription"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_ASD)));
                                    EXPECT_CALL(*handler, get("domainSpecificSID"))
                                        .WillOnce(testing::Return(kvdb::mocks::kvdbGetOk(VALID_DSS)));
                                }))
        // end
        ));
