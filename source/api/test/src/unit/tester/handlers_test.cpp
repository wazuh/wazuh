/**
 * @file handlers_test.cpp
 * @brief Unit tests for tester handlers.
 *
 * This file contains unit tests for the tester handlers, which are responsible for processing tester-related requests.
 * The tests cover various scenarios, including successful and failed requests, and different combinations of
 * parameters. The tests use a mock tester object to simulate tester data and behavior.
 *
 */
#include <gtest/gtest.h>

#include <api/policy/handlers.hpp>
#include <api/tester/handlers.hpp>

#include <api/policy/mockPolicy.hpp>
#include <router/mockTester.hpp>
#include <store/mockStore.hpp>

#include <api/adapter.hpp>
#include <eMessages/tester.pb.h>

using namespace api::policy::mocks;
using namespace api::tester::handlers;
using namespace store::mocks;
using namespace tester::mocks;


/***
 * @brief Represent the type signature of the all function to test
 *
 * The handlers is created with a function that return the handler to test.
 */
using GetHandlerToTest = std::function<api::HandlerSync(const std::shared_ptr<router::ITesterAPI>&)>;
using GetHandlerToTestComplement = std::function<api::HandlerSync(const std::shared_ptr<router::ITesterAPI>&,
                                                                  const std::shared_ptr<api::policy::IPolicy>&)>;
using GetHandlerToTestComplementStore =
    std::function<api::HandlerAsync(const std::shared_ptr<router::ITesterAPI>&, const std::shared_ptr<MockStoreRead>&)>;
/**
 * @brief Represent the type signature of the expected function
 *
 * The expected function return the response of the handler.
 */
using ExpectedFn = std::function<api::wpResponse(const std::shared_ptr<MockTesterAPI>&)>;
using ExpectedFnComplement =
    std::function<api::wpResponse(const std::shared_ptr<MockTesterAPI>&, const std::shared_ptr<MockPolicy>&)>;
using ExpectedFnComplementStore =
    std::function<api::wpResponse(const std::shared_ptr<MockTesterAPI>&,
                                  const std::shared_ptr<MockStoreRead>&,
                                  std::function<void(const base::utils::wazuhProtocol::WazuhResponse&)>)>;
/**
 * @brief Test parameters.
 * @param getHandlerFn Function that return the handler to test.
 * @param params Parameters to pass to the handler.
 * @param expectedFn Function that return the expected response.
 */
using TestRouterT = std::tuple<GetHandlerToTest, json::Json, ExpectedFn>;
using TestRouterTComplement = std::tuple<GetHandlerToTestComplement, json::Json, ExpectedFnComplement>;
using TestRouterTComplementStore = std::tuple<GetHandlerToTestComplementStore, json::Json, ExpectedFnComplementStore>;
/**
 * @brief Describe the behaviour of the handler (mocks function)
 *
 * Its used for build a success or fail response
 */
using Behaviour = std::function<void(std::shared_ptr<MockTesterAPI>)>;
using BehaviourComplement = std::function<void(std::shared_ptr<MockTesterAPI>, std::shared_ptr<MockPolicy>)>;
using BehaviourComplementStore = std::function<void(std::shared_ptr<MockTesterAPI>, std::shared_ptr<MockStoreRead>)>;
/**
 * @brief Describe the behaviour of the handler (mocks function) with return
 * json::Json is the return type
 *
 * Its used for build a success or fail response
 */
using BehaviourWRet = std::function<json::Json(std::shared_ptr<MockTesterAPI>)>;
using BehaviourWRetComplement = std::function<json::Json(std::shared_ptr<MockTesterAPI>, std::shared_ptr<MockPolicy>)>;
using BehaviourWRetComplementStore =
    std::function<json::Json(std::shared_ptr<MockTesterAPI>,
                             std::shared_ptr<MockStoreRead>,
                             std::function<void(const base::utils::wazuhProtocol::WazuhResponse&)>)>;

const std::string STATUS_PATH = "/status";
const std::string ERROR_PATH = "/error";
const std::string STATUS_OK = "OK";
const std::string STATUS_ERROR = "ERROR";

static ExpectedFn success(const Behaviour& behaviour = {})
{
    return [behaviour](const std::shared_ptr<MockTesterAPI>& router) -> api::wpResponse
    {
        if (behaviour)
        {
            behaviour(router);
        }
        json::Json dataR;
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

static ExpectedFn successWPayload(const BehaviourWRet& behaviour)
{
    if (!behaviour)
    {
        throw std::runtime_error("Behaviour with return must be defined");
    }
    return [behaviour](const std::shared_ptr<MockTesterAPI>& router) -> api::wpResponse
    {
        json::Json dataR = behaviour(router);
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

static ExpectedFn failure(const Behaviour& behaviour = {})
{
    return [behaviour](const std::shared_ptr<MockTesterAPI>& router) -> api::wpResponse
    {
        if (behaviour)
        {
            behaviour(router);
        }
        json::Json failStatus;
        failStatus.setString(STATUS_ERROR, STATUS_PATH);
        return api::wpResponse(failStatus);
    };
}

static ExpectedFn failureWPayload(const BehaviourWRet& behaviour = {})
{
    if (!behaviour)
    {
        throw std::runtime_error("Behaviour with return must be defined");
    }
    return [behaviour](const std::shared_ptr<MockTesterAPI>& router) -> api::wpResponse
    {
        json::Json dataR = behaviour(router);
        dataR.setString(STATUS_ERROR, STATUS_PATH);
        return api::wpResponse(dataR);
    };
}

static ExpectedFnComplement failureWPayloadComplement(const BehaviourWRetComplement& behaviour = {})
{
    if (!behaviour)
    {
        throw std::runtime_error("Behaviour with return must be defined");
    }
    return [behaviour](const std::shared_ptr<MockTesterAPI>& router,
                       const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse
    {
        json::Json dataR = behaviour(router, policy);
        dataR.setString(STATUS_ERROR, STATUS_PATH);
        return api::wpResponse(dataR);
    };
}

static ExpectedFnComplementStore failureWPayloadComplementStore(const BehaviourWRetComplementStore& behaviour = {})
{
    if (!behaviour)
    {
        throw std::runtime_error("Behaviour with return must be defined");
    }
    return
        [behaviour](const std::shared_ptr<MockTesterAPI>& router,
                    const std::shared_ptr<MockStoreRead>& store,
                    std::function<void(const base::utils::wazuhProtocol::WazuhResponse&)> callback) -> api::wpResponse
    {
        json::Json dataR = behaviour(router, store, callback);
        dataR.setString(STATUS_ERROR, STATUS_PATH);
        return api::wpResponse(dataR);
    };
}

static ExpectedFnComplement succesComplement(const BehaviourComplement& behaviour = {})
{
    if (!behaviour)
    {
        throw std::runtime_error("Behaviour with return must be defined");
    }
    return [behaviour](const std::shared_ptr<MockTesterAPI>& router,
                       const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse
    {
        behaviour(router, policy);
        json::Json dataR;
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

static ExpectedFnComplement succesWPayloadComplement(const BehaviourWRetComplement& behaviour = {})
{
    if (!behaviour)
    {
        throw std::runtime_error("Behaviour with return must be defined");
    }
    return [behaviour](const std::shared_ptr<MockTesterAPI>& router,
                       const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse
    {
        json::Json dataR = behaviour(router, policy);
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

static ExpectedFnComplementStore successWPayloadComplementStore(const BehaviourWRetComplementStore& behaviour = {})
{
    if (!behaviour)
    {
        throw std::runtime_error("Behaviour with return must be defined");
    }
    return
        [behaviour](const std::shared_ptr<MockTesterAPI>& router,
                    const std::shared_ptr<MockStoreRead>& store,
                    std::function<void(const base::utils::wazuhProtocol::WazuhResponse&)> callback) -> api::wpResponse
    {
        json::Json dataR = behaviour(router, store, callback);
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

// Valid params
const std::string ENVIRONMENT_NAME = "Production";
const std::string POLICY_NAME = "policy/name/0";
const uint32_t LIFESPAM = 1234;
const std::string DESCRIPTION = "This is a production environment";
const router::env::Sync POLICY_SYNC = router::env::Sync::UPDATED;
const router::env::State ENTRY_STATE = router::env::State::UNKNOWN;
const uint32_t UPTIME = 1234;
const std::string EVENT = "I am a dummy event";

namespace routerTest
{

const std::string inline stateToString(router::env::State state)
{
    const std::unordered_map<router::env::State, std::string> stateStrings {{router::env::State::UNKNOWN, "UNKNOWN"},
                                                                            {router::env::State::DISABLED, "DISABLED"},
                                                                            {router::env::State::ENABLED, "ENABLED"}};

    auto it = stateStrings.find(state);
    return (it != stateStrings.end()) ? it->second : "InvalidState";
}

const std::string inline syncToString(router::env::Sync sync)
{
    const std::unordered_map<router::env::Sync, std::string> syncStrings {{router::env::Sync::UNKNOWN, "UNKNOWN"},
                                                                          {router::env::Sync::UPDATED, "UPDATED"},
                                                                          {router::env::Sync::OUTDATED, "OUTDATED"},
                                                                          {router::env::Sync::ERROR, "ERROR"}};

    auto it = syncStrings.find(sync);
    return (it != syncStrings.end()) ? it->second : "InvalidSync";
}

/**
 * @brief User for build the params of the handler in a easy way
 *
 */
struct JParams
{
    std::optional<std::string> m_environmentName;
    std::optional<std::string> m_policyName;
    std::optional<uint32_t> m_lifespam;
    std::optional<std::string> m_description;

    std::optional<std::string> m_message;
    std::optional<std::string> m_location;
    std::optional<std::string> m_queue;

    std::optional<router::test::Options::TraceLevel> m_traceLevel;

    std::optional<std::vector<std::string>> m_assets;
    std::optional<std::vector<std::string>> m_namespaces;

    std::optional<router::env::Sync> m_policySync;
    std::optional<router::env::State> m_entryState;
    std::optional<uint32_t> m_lastUse;
    bool m_hasSessionPath;

    JParams(const std::string& name, const std::string& policy, const uint32_t lifespam, bool hasSessionPath = true)
        : m_environmentName(name)
        , m_policyName(policy)
        , m_lifespam(lifespam)
    {
        m_hasSessionPath = hasSessionPath;
    }

    JParams(const std::string& name, bool hasSessionPath = true)
        : m_environmentName(name)
    {
        m_hasSessionPath = hasSessionPath;
    }

    JParams& policySync(router::env::Sync pSync)
    {
        m_policySync = pSync;
        return *this;
    }

    JParams& entryState(router::env::State eState)
    {
        m_entryState = eState;
        return *this;
    }

    JParams& lastUse(const uint32_t lastUse)
    {

        m_lastUse = lastUse;
        return *this;
    }

    JParams& event(const std::string& message)
    {
        m_message = message;
        return *this;
    }

    JParams& traceLevel(router::test::Options::TraceLevel traceLevel)
    {
        m_traceLevel = traceLevel;
        return *this;
    }

    JParams& location(const std::string& location)
    {
        m_location = location;
        return *this;
    }

    JParams& queue(const std::string& queue)
    {
        m_queue = queue;
        return *this;
    }

    JParams& namespaces(const std::vector<std::string>& namespaces)
    {

        m_namespaces = namespaces;
        return *this;
    }

    JParams& assets(const std::vector<std::string>& assets)
    {

        m_assets = assets;
        return *this;
    }

    std::string traceLevelToString(router::test::Options::TraceLevel level) const
    {
        switch (level)
        {
            case router::test::Options::TraceLevel::NONE: return "NONE";
            case router::test::Options::TraceLevel::ASSET_ONLY: return "ASSET_ONLY";
            case router::test::Options::TraceLevel::ALL: return "ALL";
            default: return "UNKNOWN";
        }
    }

    // cast to json
    operator json::Json() const
    {
        json::Json j;
        std::string path = "/";
        if (m_hasSessionPath)
        {
            path += "session/";
        }
        if (m_environmentName)
        {
            j.setString(m_environmentName.value(), path + "name");
        }
        if (m_policyName)
        {
            j.setString(m_policyName.value(), path + "policy");
        }
        if (m_namespaces)
        {
            j.setArray("/namespaces");
            for (const auto& ns : m_namespaces.value())
            {
                j.appendString(ns, "/namespaces");
            }
        }
        if (m_assets)
        {
            j.setArray("/asset_trace");
            for (const auto& ns : m_namespaces.value())
            {
                j.appendString(ns, "/asset_trace");
            }
        }
        if (m_location)
        {
            j.setString(m_location.value(), path + "location");
        }
        if (m_queue)
        {
            j.setString(m_queue.value(), path + "queue");
        }
        if (m_policySync)
        {
            j.setString(syncToString(m_policySync.value()), path + "policySync");
        }
        if (m_entryState)
        {
            j.setString(stateToString(m_entryState.value()), path + "entrySync");
        }
        if (m_lastUse)
        {
            j.setInt(m_lastUse.value(), path + "lastUse");
        }
        if (m_message)
        {
            j.setString(m_message.value(), path + "message");
        }
        if (m_traceLevel)
        {
            j.setString(traceLevelToString(m_traceLevel.value()), path + "trace_level");
        }
        return j;
    }

    // cast to string
    operator std::string() const { return json::Json(*this).str(); }
};

} // namespace routerTest

class TesterHandlerTest : public ::testing::TestWithParam<TestRouterT>
{
protected:
    std::shared_ptr<MockTesterAPI> m_tester;

    void SetUp() override { m_tester = std::make_shared<MockTesterAPI>(); }

    void TearDown() override { m_tester.reset(); }
};

TEST_P(TesterHandlerTest, processRequest)
{
    const auto [getHandlerFn, jparams, expectedFn] = GetParam();

    auto expectedResponse = expectedFn(m_tester);
    auto request = api::wpRequest::create("router.command", "test", jparams);

    auto response = getHandlerFn(m_tester)(request);

    if (expectedResponse.data().getString(STATUS_PATH) == STATUS_ERROR)
    {
        EXPECT_STREQ(expectedResponse.data().getString(ERROR_PATH).value().c_str(),
                     response.data().getString(ERROR_PATH).value().c_str());
    }
    else
    {
        ASSERT_EQ(expectedResponse.data(), response.data());
    }
}

INSTANTIATE_TEST_SUITE_P(
    HandlerTesterTest,
    TesterHandlerTest,
    testing::Values(
        // [sessionPost]: Fail
        TestRouterT(sessionPost,
                    routerTest::JParams(ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM, false),
                    failureWPayload(
                        [](auto tester) -> json::Json
                        {
                            const auto msg = "Session parameter is required";
                            auto expected = json::Json();
                            expected.setString(msg, "/error");
                            return expected;
                        })),
        TestRouterT(sessionPost,
                    routerTest::JParams(ENVIRONMENT_NAME, "", LIFESPAM),
                    failureWPayload(
                        [](auto tester) -> json::Json
                        {
                            const auto msg = "Invalid policy for session: Name cannot be empty";
                            auto expected = json::Json();
                            expected.setString(msg, "/error");
                            return expected;
                        })),
        TestRouterT(sessionPost,
                    routerTest::JParams(ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM),
                    failureWPayload(
                        [](auto tester) -> json::Json
                        {
                            std::string header = "Error creating session: ";
                            const auto msg = "error";
                            base::OptError error = base::Error {msg};
                            EXPECT_CALL(*tester, postTestEntry(testing::_)).WillOnce(::testing::Return(error));
                            auto expected = json::Json();
                            expected.setString(header + msg, "/error");
                            return expected;
                        })),
        // [sessionPost]: Success
        TestRouterT(
            sessionPost,
            routerTest::JParams(ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM),
            success([](auto tester)
                    { EXPECT_CALL(*tester, postTestEntry(testing::_)).WillOnce(::testing::Return(std::nullopt)); })),
        // [sessionDelete]: Fail
        TestRouterT(sessionDelete,
                    routerTest::JParams(ENVIRONMENT_NAME, "", LIFESPAM),
                    failureWPayload(
                        [](auto tester)
                        {
                            std::string header = "Error deleting session: ";
                            const auto msg = "error";
                            base::OptError error = base::Error {msg};
                            EXPECT_CALL(*tester, deleteTestEntry(testing::_)).WillOnce(::testing::Return(error));
                            auto expected = json::Json();
                            expected.setString(header + msg, "/error");
                            return expected;
                        })),
        // [sessionDelete]: Success
        TestRouterT(
            sessionDelete,
            routerTest::JParams(ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM),
            success([](auto tester)
                    { EXPECT_CALL(*tester, deleteTestEntry(testing::_)).WillOnce(::testing::Return(std::nullopt)); })),
        TestRouterT(sessionReload,
                    routerTest::JParams(ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM),
                    failureWPayload(
                        [](auto tester)
                        {
                            std::string header = "Error reloading session: ";
                            const auto msg = "error";
                            base::OptError error = base::Error {msg};
                            EXPECT_CALL(*tester, reloadTestEntry(testing::_)).WillOnce(::testing::Return(error));
                            auto expected = json::Json();
                            expected.setString(header + msg, "/error");
                            return expected;
                        })),
        TestRouterT(sessionReload,
                    routerTest::JParams(ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM),
                    success(
                        [](auto tester) {
                            EXPECT_CALL(*tester, reloadTestEntry(testing::_)).WillOnce(::testing::Return(std::nullopt));
                        }))));

class TesterHandlerTestComplement : public ::testing::TestWithParam<TestRouterTComplement>
{
protected:
    std::shared_ptr<MockPolicy> m_policy;
    std::shared_ptr<MockTesterAPI> m_tester;

    void SetUp() override
    {
        m_tester = std::make_shared<MockTesterAPI>();
        m_policy = std::make_shared<MockPolicy>();
    }

    void TearDown() override
    {
        m_tester.reset();
        m_policy.reset();
    }
};

TEST_P(TesterHandlerTestComplement, processRequest)
{
    const auto [getHandlerFn, jparams, expectedFn] = GetParam();

    auto expectedResponse = expectedFn(m_tester, m_policy);
    auto request = api::wpRequest::create("router.command", "test", jparams);

    auto response = getHandlerFn(m_tester, m_policy)(request);

    if (expectedResponse.data().getString(STATUS_PATH) == STATUS_ERROR)
    {
        EXPECT_STREQ(expectedResponse.data().getString(ERROR_PATH).value().c_str(),
                     response.data().getString(ERROR_PATH).value().c_str());
    }
    else
    {
        if (response.data().getString("/session/policy_sync").has_value())
        {
            EXPECT_STREQ(expectedResponse.data().getString("/policy_sync").value().c_str(),
                         response.data().getString("/session/policy_sync").value().c_str());
        }
        else if (response.data().getArray("/sessions").has_value())
        {
            EXPECT_STREQ(expectedResponse.data().getString("/policy_sync").value().c_str(),
                         response.data().getArray("/sessions").value()[0].getString("/policy_sync").value().c_str());
        }
        else
        {
            ASSERT_EQ(expectedResponse.data(), response.data());
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    HandlerTesterTest,
    TesterHandlerTestComplement,
    testing::Values(
        // [sessionGet]: Fail
        TestRouterTComplement(sessionGet,
                              routerTest::JParams("", false),
                              failureWPayloadComplement(
                                  [](auto tester, auto policy) -> json::Json
                                  {
                                      std::string header = "Error getting session: ";
                                      const auto msg = "Name cannot be empty";
                                      base::OptError error = base::Error {msg};
                                      EXPECT_CALL(*tester, getTestEntry(testing::_))
                                          .WillOnce(::testing::Return(error.value()));
                                      auto expected = json::Json();
                                      expected.setString(header + msg, "/error");
                                      return expected;
                                  })),
        // [sessionGet]: Success
        TestRouterTComplement(
            sessionGet,
            routerTest::JParams(ENVIRONMENT_NAME, false),
            succesWPayloadComplement(
                [](auto tester, auto policy) -> json::Json
                {
                    router::test::Entry entry(router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM});
                    EXPECT_CALL(*tester, getTestEntry(testing::_)).WillOnce(::testing::Return(entry));

                    auto error = base::Error {"ERROR"};
                    EXPECT_CALL(*policy, getHash(testing::_)).WillOnce(::testing::Return(error));
                    entry.policySync(router::env::Sync::ERROR);
                    auto res = json::Json(R"({})");
                    res.setString(routerTest::syncToString(entry.policySync()), "/policy_sync");
                    return res;
                })),
        TestRouterTComplement(
            sessionGet,
            routerTest::JParams(ENVIRONMENT_NAME, false),
            succesWPayloadComplement(
                [](auto tester, auto policy) -> json::Json
                {
                    router::test::Entry entry(router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM});
                    EXPECT_CALL(*tester, getTestEntry(testing::_)).WillOnce(::testing::Return(entry));

                    EXPECT_CALL(*policy, getHash(testing::_)).WillOnce(::testing::Return("hash"));
                    entry.policySync(router::env::Sync::OUTDATED);
                    auto res = json::Json(R"({})");
                    res.setString(routerTest::syncToString(entry.policySync()), "/policy_sync");
                    return res;
                })),
        // [tableGet]: Success
        TestRouterTComplement(
            tableGet,
            routerTest::JParams(ENVIRONMENT_NAME, false),
            succesWPayloadComplement(
                [](auto tester, auto policy) -> json::Json
                {
                    router::test::Entry entry(router::test::EntryPost {ENVIRONMENT_NAME, POLICY_NAME, LIFESPAM});
                    std::list<router::test::Entry> entries;
                    entries.push_back(entry);
                    EXPECT_CALL(*tester, getTestEntries()).WillRepeatedly(::testing::Return(entries));

                    auto error = base::Error {"ERROR"};
                    EXPECT_CALL(*policy, getHash(testing::_)).WillOnce(::testing::Return(error));
                    entry.policySync(router::env::Sync::ERROR);
                    auto res = json::Json(R"({})");
                    res.setString(routerTest::syncToString(entry.policySync()), "/policy_sync");
                    return res;
                }))));

namespace eTester = ::com::wazuh::api::engine::tester;
eTester::Result getResultFromOutput(const ::router::test::Output& output)
{
    eTester::Result result {};

    // Set event
    auto resProtoEvent = eMessage::eMessageFromJson<google::protobuf::Value>(output.event()->str());
    if (std::holds_alternative<base::Error>(resProtoEvent))
    {
        throw std::runtime_error {std::get<base::Error>(resProtoEvent).message}; // Should never happen
    }
    auto& protoEvent = std::get<google::protobuf::Value>(resProtoEvent);
    result.mutable_output()->CopyFrom(protoEvent);

    // Set traces
    for (const auto& [assetName, assetTrace] : output.traceList())
    {
        eTester::Result_AssetTrace eTrace {};
        eTrace.set_asset(assetName);
        eTrace.set_success(assetTrace.success);
        for (const auto& trace : assetTrace.traces)
        {
            eTrace.add_traces(trace);
        }

        result.mutable_asset_traces()->Add(std::move(eTrace));
    }

    return result;
}

class TesterHandlerTestComplementStore : public ::testing::TestWithParam<TestRouterTComplementStore>
{
protected:
    std::shared_ptr<MockStoreRead> m_store;
    std::shared_ptr<MockTesterAPI> m_tester;

    void SetUp() override
    {
        m_tester = std::make_shared<MockTesterAPI>();
        m_store = std::make_shared<MockStoreRead>();
    }

    void TearDown() override
    {
        m_tester.reset();
        m_store.reset();
    }
};

TEST_P(TesterHandlerTestComplementStore, processRequest)
{
    const auto [getHandlerFn, jparams, expectedFn] = GetParam();

    auto strResponse = std::make_shared<std::string>();
    auto callbackFn = [&strResponse](const base::utils::wazuhProtocol::WazuhResponse& res)
    {
        *strResponse = res.toString();
    };

    auto expectedResponse = expectedFn(m_tester, m_store, callbackFn);
    auto request = api::wpRequest::create("router.command", "test", jparams);

    getHandlerFn(m_tester, m_store)(request, callbackFn);
    auto response = json::Json {strResponse->c_str()};

    if (expectedResponse.data().getString(STATUS_PATH) == STATUS_ERROR)
    {
        EXPECT_STREQ(expectedResponse.data().getString(ERROR_PATH).value().c_str(),
                     response.getJson("/data").value().getString("/error").value().c_str());
    }
    else
    {
        ASSERT_EQ(expectedResponse.data(), response);
    }
}

INSTANTIATE_TEST_SUITE_P(
    HandlerTesterTest,
    TesterHandlerTestComplementStore,
    testing::Values(
        // [runPost]: TraceLevel: None, Timeout Error
        TestRouterTComplementStore(
            runPost,
            routerTest::JParams(ENVIRONMENT_NAME, false).event("i am a message").queue("49").location("here"),
            failureWPayloadComplementStore(
                [](auto tester, auto store, auto callback) -> json::Json
                {
                    std::string message = "49:here:i am a message";
                    base::Error error {"error"};

                    EXPECT_CALL(*tester, ingestTest(message, testing::_, testing::_))
                        .WillOnce(::testing::Return(error));
                    auto expected = json::Json();
                    expected.setString(error.message, "/error");

                    base::utils::wazuhProtocol::WazuhResponse response {};
                    response.data(expected);
                    callback(response);

                    return expected;
                })),
        TestRouterTComplementStore(runPost,
                                   routerTest::JParams(ENVIRONMENT_NAME, false)
                                       .event("i am a message")
                                       .queue("49")
                                       .location("here")
                                       .traceLevel(router::test::Options::TraceLevel::ASSET_ONLY),
                                   failureWPayloadComplementStore(
                                       [](auto tester, auto store, auto callback) -> json::Json
                                       {
                                           auto expected = json::Json();
                                           expected.setString("Namespaces parameter is required", "/error");

                                           base::utils::wazuhProtocol::WazuhResponse response {};
                                           response.data(expected);
                                           callback(response);

                                           return expected;
                                       })),
        TestRouterTComplementStore(runPost,
                                   routerTest::JParams(ENVIRONMENT_NAME, false)
                                       .event("i am a message")
                                       .queue("49")
                                       .location("here")
                                       .traceLevel(router::test::Options::TraceLevel::ASSET_ONLY)
                                       .namespaces({"ns1", "ns2"}),
                                   failureWPayloadComplementStore(
                                       [](auto tester, auto store, auto callback) -> json::Json
                                       {
                                           auto error = "error getting assets";
                                           EXPECT_CALL(*tester, getAssets(testing::_))
                                               .WillOnce(::testing::Return(base::Error {error}));

                                           auto expected = json::Json();
                                           expected.setString(error, "/error");

                                           base::utils::wazuhProtocol::WazuhResponse response {};
                                           response.data(expected);
                                           callback(response);

                                           return expected;
                                       })),
        TestRouterTComplementStore(
            runPost,
            routerTest::JParams(ENVIRONMENT_NAME, false)
                .event("i am a message")
                .queue("49")
                .location("here")
                .traceLevel(router::test::Options::TraceLevel::ASSET_ONLY)
                .namespaces({"ns1", "ns2"}),
            failureWPayloadComplementStore(
                [](auto tester, auto store, auto callback) -> json::Json
                {
                    EXPECT_CALL(*tester, getAssets(testing::_))
                        .WillOnce(
                            ::testing::Return(std::unordered_set<std::string> {"policy/wazuh/0", "policy/wazuh/1"}));
                    EXPECT_CALL(*store, getNamespace(testing::_)).WillOnce(::testing::Return(std::nullopt));

                    auto expected = json::Json();
                    expected.setString("Asset policy/wazuh/1 not found in store", "/error");

                    base::utils::wazuhProtocol::WazuhResponse response {};
                    response.data(expected);
                    callback(response);

                    return expected;
                }))));
