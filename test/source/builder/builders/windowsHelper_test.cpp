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
using BuildMapT = std::tuple<json::Json, bool>;
class WindowsBuildMaps : public WindowsHelper<BuildMapT>
{
};

TEST_P(WindowsBuildMaps, builds)
{
    const std::string dstFild = "dstField";
    const std::string srcFild = "$sidList";

    auto [initialState, shouldPass] = GetParam();
    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(DB_NAME_1, "builder_test")).WillOnce(testing::Return(kvdbHandler));
    
    if (shouldPass)
    {
        EXPECT_CALL(*kvdbHandler, get(srcFild)).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk()));
        ASSERT_NO_THROW(m_builder(dstFild, "name", {DB_NAME_1, srcFild}, m_failDef));
    }
    else
    {
        EXPECT_CALL(*kvdbHandler, get(srcFild)).WillOnce(testing::Return(kvdb::mocks::kvdbGetError("")));
        ASSERT_THROW(m_builder(dstFild, "name", {DB_NAME_1, srcFild}, m_failDef), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    WindowsSidDesc,
    WindowsBuildMaps,
    ::testing::Values(
        // Ok map
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(VALID_DSS), true),
        // Empty map
        BuildMapT(MakeInitialState(), false),
        // Empty accountSIDDescription
        BuildMapT(MakeInitialState().setDSS(VALID_DSS), false),
        // Empty domainSpecificSID
        BuildMapT(MakeInitialState().setASD(VALID_ASD), false),
        // Empty accountSIDDescription and domainSpecificSID
        BuildMapT(MakeInitialState().setASD(R"( {} )").setDSS(R"( {} )"), false),
        // invalid types of accountSIDDescription
        BuildMapT(MakeInitialState().setASD(R"( null )").setDSS(VALID_DSS), false),
        BuildMapT(MakeInitialState().setASD(R"( 123 )").setDSS(VALID_DSS), false),
        BuildMapT(MakeInitialState().setASD(R"( "asd" )").setDSS(VALID_DSS), false),
        BuildMapT(MakeInitialState().setASD(R"( false )").setDSS(VALID_DSS), false),
        BuildMapT(MakeInitialState().setASD(R"( ["null"] )").setDSS(VALID_DSS), false),
        BuildMapT(MakeInitialState().setASD(R"( [{"key": "value"}] )").setDSS(VALID_DSS), false),
        // invalid types of domainSpecificSID
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( null )"), false),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( 123 )"), false),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( "asd" )"), false),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( false )"), false),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( ["null"] )"), false),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( [{"key": "value"}] )"), false),
        // Value of accountSIDDescription is not string
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": null} )").setDSS(VALID_DSS), false),
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": 123} )").setDSS(VALID_DSS), false),
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": false} )").setDSS(VALID_DSS), false),
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": ["null"]} )").setDSS(VALID_DSS), false),
        BuildMapT(MakeInitialState().setASD(R"( {"S-1-5-32-544": [{"key": "value"}]} )").setDSS(VALID_DSS), false),
        // Value of domainSpecificSID is not string
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": null} )"), false),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": 123} )"), false),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": false} )"), false),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": ["null"]} )"), false),
        BuildMapT(MakeInitialState().setASD(VALID_ASD).setDSS(R"( {"498": [{"key": "value"}]} )"), false)
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
        EXPECT_CALL(*kvdbHandler, get(params[1])).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk()));
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
                             WindowsBuildParamsT({"$ref", "notRef"}, false),
                             // Unknown db
                             WindowsBuildParamsT({"test_db1", "$ref"}, false)
                             // end
                             ));

// Test of get description from DB [reference source json value, expected description (if is not empty then should
// pass)]
using WindowsSidDescExecT = std::tuple<std::string, std::vector<std::string>>;
class WindowsSidDescExec : public WindowsHelper<WindowsSidDescExecT>
{
};

TEST_P(WindowsSidDescExec, exec)
{

    auto [listStrValue, expectedArrayStr] = GetParam();
    std::vector<json::Json> expectedArray;
    for (auto& str : expectedArrayStr)
    {
        json::Json item {};
        item.setString(str);
        expectedArray.push_back(std::move(item));
    }

    const std::string dstFieldPath = "/dstField";
    const std::string srcListPath = "/winList";
    const std::string srcListRef = "$winList";
    const bool shouldPass = !expectedArray.empty();

    auto kvdbHandler = std::make_shared<kvdb::mocks::MockKVDBHandler>();
    EXPECT_CALL(*m_kvdbManager, getKVDBHandler(DB_NAME_1, "builder_test")).WillOnce(testing::Return(kvdbHandler));
    EXPECT_CALL(*kvdbHandler, get(srcListRef)).WillOnce(testing::Return(kvdb::mocks::kvdbGetOk()));
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
    if (shouldPass)
    {
        ASSERT_TRUE(res.success());
        auto jArray = res.payload()->getArray(dstFieldPath);
        ASSERT_TRUE(jArray.has_value());
        ASSERT_EQ(jArray.value().size(), expectedArray.size());
        for (size_t i = 0; i < expectedArray.size(); ++i)
        {
            ASSERT_EQ(jArray.value()[i], expectedArray[i]);
        }
    }
    else
    {
        ASSERT_TRUE(res.failure());
    }
}

INSTANTIATE_TEST_SUITE_P(
    WindowsSidDesc,
    WindowsSidDescExec,
    ::testing::Values(
        // Single result
        WindowsSidDescExecT(R"( "%{S-1-5-32-544}" )", {"Administrators"}),
        WindowsSidDescExecT(R"( "%{S-1-5-32-545}" )", {"Users"}),
        WindowsSidDescExecT(R"( "%{S-1-5-32-546}" )", {"Guests"}),
        WindowsSidDescExecT(R"( "%{S-1-5-32-547}" )", {"Power Users"}),
        WindowsSidDescExecT(R"( "%{S-1-5-32-123-54-65}" )", {"S-1-5-32-123-54-65"}),
        // Start with S-1-5-21 and end with numbers
        // https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/understand-security-identifiers#sids-added-by-windows-server-2012-and-later-versions
        WindowsSidDescExecT(R"( "%{S-1-5-21-1004336348-1177238915-682003330-512}" )", {"Domain Admins"}),
        // Match 5-11-21 and end with numbers (not valid)
        WindowsSidDescExecT(R"( "%{S-1-5-21-1004336348-1177238915-682003330-4000}" )",
                            {"S-1-5-21-1004336348-1177238915-682003330-4000"}),
        // TODO Check multiple sids
        WindowsSidDescExecT(R"( "%{S-1-5-32-544} %{S-1-5-32-123-54-65}" )", {"Administrators", "S-1-5-32-123-54-65"}),
        // Unexpected values
        WindowsSidDescExecT("", {}),
        WindowsSidDescExecT(R"( null )", {}),
        WindowsSidDescExecT(R"( 123 )", {}),
        WindowsSidDescExecT(R"( false )", {}),
        WindowsSidDescExecT(R"( ["null"] )", {}),
        WindowsSidDescExecT(R"( [{"key": "value"}] )", {})
        // end
        ));
