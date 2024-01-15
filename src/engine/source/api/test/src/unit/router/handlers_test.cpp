/**
 * @file handlers_test.cpp
 * @brief Unit tests for router handlers.
 *
 * This file contains unit tests for the router handlers, which are responsible for processing router-related requests.
 * The tests cover various scenarios, including successful and failed requests, and different combinations of
 * parameters. The tests use a mock router object to simulate router data and behavior.
 *
 */
#include <gtest/gtest.h>

#include <api/policy/handlers.hpp>
#include <api/router/handlers.hpp>

#include <api/policy/mockPolicy.hpp>
#include <router/mockRouter.hpp>

using namespace api::policy::mocks;
using namespace api::router::handlers;
using namespace router::mocks;

/***
 * @brief Represent the type signature of the all function to test
 *
 * The handlers is created with a function that return the handler to test.
 */
using GetHandlerToTest = std::function<api::HandlerSync(const std::shared_ptr<router::IRouterAPI>&)>;
using GetHandlerToTestComplement = std::function<api::HandlerSync(const std::shared_ptr<router::IRouterAPI>&,
                                                                  const std::shared_ptr<api::policy::IPolicy>&)>;

/**
 * @brief Represent the type signature of the expected function
 *
 * The expected function return the response of the handler.
 */
using ExpectedFn = std::function<api::wpResponse(const std::shared_ptr<MockRouterAPI>&)>;
using ExpectedFnComplement =
    std::function<api::wpResponse(const std::shared_ptr<MockRouterAPI>&, const std::shared_ptr<MockPolicy>&)>;
/**
 * @brief Test parameters.
 * @param getHandlerFn Function that return the handler to test.
 * @param params Parameters to pass to the handler.
 * @param expectedFn Function that return the expected response.
 */
using TestRouterT = std::tuple<GetHandlerToTest, json::Json, ExpectedFn>;
using TestRouterTComplement = std::tuple<GetHandlerToTestComplement, json::Json, ExpectedFnComplement>;

/**
 * @brief Describe the behaviour of the handler (mocks function)
 *
 * Its used for build a success or fail response
 */
using Behaviour = std::function<void(std::shared_ptr<MockRouterAPI>)>;
using BehaviourComplement = std::function<void(std::shared_ptr<MockRouterAPI>, std::shared_ptr<MockPolicy>)>;
/**
 * @brief Describe the behaviour of the handler (mocks function) with return
 * json::Json is the return type
 *
 * Its used for build a success or fail response
 */
using BehaviourWRet = std::function<json::Json(std::shared_ptr<MockRouterAPI>)>;
using BehaviourWRetComplement = std::function<json::Json(std::shared_ptr<MockRouterAPI>, std::shared_ptr<MockPolicy>)>;

const std::string STATUS_PATH = "/status";
const std::string ERROR_PATH = "/error";
const std::string STATUS_OK = "OK";
const std::string STATUS_ERROR = "ERROR";

static ExpectedFn success(const Behaviour& behaviour = {})
{
    return [behaviour](const std::shared_ptr<MockRouterAPI>& router) -> api::wpResponse
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
    return [behaviour](const std::shared_ptr<MockRouterAPI>& router) -> api::wpResponse
    {
        json::Json dataR = behaviour(router);
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

static ExpectedFn failure(const Behaviour& behaviour = {})
{
    return [behaviour](const std::shared_ptr<MockRouterAPI>& router) -> api::wpResponse
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
    return [behaviour](const std::shared_ptr<MockRouterAPI>& router) -> api::wpResponse
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
    return [behaviour](const std::shared_ptr<MockRouterAPI>& router,
                       const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse
    {
        json::Json dataR = behaviour(router, policy);
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
    return [behaviour](const std::shared_ptr<MockRouterAPI>& router,
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
    return [behaviour](const std::shared_ptr<MockRouterAPI>& router,
                       const std::shared_ptr<MockPolicy>& policy) -> api::wpResponse
    {
        json::Json dataR = behaviour(router, policy);
        dataR.setString(STATUS_OK, STATUS_PATH);
        return api::wpResponse {dataR};
    };
}

// Valid params
const std::string ENVIRONMENT_NAME = "Production";
const std::string POLICY_NAME = "policy/name/0";
const std::string FILTER_NAME = "filter/name/0";
const uint32_t PRIORITY = 70;
const std::string DESCRIPTION = "This is a production environment";
const router::env::Sync POLICY_SYNC = router::env::Sync::UPDATED;
const router::env::State ENTRY_STATE = router::env::State::UNKNOWN;
const uint32_t UPTIME = 1234;
const std::string EVENT = "I am a dummy event";

namespace routerProduction
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
    std::optional<std::string> m_filterName;
    std::optional<uint32_t> m_priority;
    std::optional<std::string> m_description;
    std::optional<router::env::Sync> m_policySync;
    std::optional<router::env::State> m_entryState;
    std::optional<uint32_t> m_uptime;
    std::optional<std::string> m_event;
    bool m_hasRoutePath;

    JParams(const std::string& name,
            const std::string& policy,
            const std::string& filter,
            const uint32_t priority,
            bool hasRoutePath = true)
        : m_environmentName(name)
        , m_policyName(policy)
        , m_filterName(filter)
        , m_priority(priority)
    {
        m_hasRoutePath = hasRoutePath;
    }

    JParams(const std::string& name, bool hasRoutePath = true)
        : m_environmentName(name)
    {
        m_hasRoutePath = hasRoutePath;
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

    JParams& uptime(const uint32_t uptime)
    {

        m_uptime = uptime;
        return *this;
    }

    JParams& event(const std::string& event)
    {
        m_event = event;
        return *this;
    }

    // cast to json
    operator json::Json() const
    {
        json::Json j;
        std::string path = "/";
        if (m_hasRoutePath)
        {
            path += "route/";
        }
        if (m_environmentName)
        {
            j.setString(m_environmentName.value(), path + "name");
        }
        if (m_policyName)
        {
            j.setString(m_policyName.value(), path + "policy");
        }
        if (m_filterName)
        {
            j.setString(m_filterName.value(), path + "filter");
        }
        if (m_priority)
        {
            j.setInt(m_priority.value(), path + "priority");
        }
        if (m_policySync)
        {
            j.setString(syncToString(m_policySync.value()), path + "policySync");
        }
        if (m_entryState)
        {
            j.setString(stateToString(m_entryState.value()), path + "entrySync");
        }
        if (m_uptime)
        {
            j.setInt(m_uptime.value(), path + "uptime");
        }
        if (m_event)
        {
            j.setString(m_event.value(), path + "event");
        }
        return j;
    }

    // cast to string
    operator std::string() const { return json::Json(*this).str(); }
};

} // namespace routerProduction

using namespace routerProduction;
class RouterHandlerTest : public ::testing::TestWithParam<TestRouterT>
{
protected:
    std::shared_ptr<MockRouterAPI> m_router;

    void SetUp() override { m_router = std::make_shared<MockRouterAPI>(); }

    void TearDown() override { m_router.reset(); }
};

TEST_P(RouterHandlerTest, processRequest)
{
    const auto [getHandlerFn, jparams, expectedFn] = GetParam();

    auto expectedResponse = expectedFn(m_router);
    auto request = api::wpRequest::create("router.command", "test", jparams);

    auto response = getHandlerFn(m_router)(request);

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
    HandlerrouterProduction,
    RouterHandlerTest,
    testing::Values(
        // [routePost]: Fail
        TestRouterT(routePost,
                    routerProduction::JParams(ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY, false),
                    failureWPayload(
                        [](auto router) -> json::Json
                        {
                            const auto msg = "Missing /route";
                            auto expected = json::Json();
                            expected.setString(msg, "/error");
                            return expected;
                        })),
        TestRouterT(routePost,
                    routerProduction::JParams(ENVIRONMENT_NAME, "", FILTER_NAME, PRIORITY),
                    failureWPayload(
                        [](auto router) -> json::Json
                        {
                            const auto msg = "Invalid policy name: Name cannot be empty";
                            auto expected = json::Json();
                            expected.setString(msg, "/error");
                            return expected;
                        })),
        TestRouterT(routePost,
                    routerProduction::JParams(ENVIRONMENT_NAME, POLICY_NAME, "", PRIORITY),
                    failureWPayload(
                        [](auto router) -> json::Json
                        {
                            const auto msg = "Invalid filter name: Name cannot be empty";
                            auto expected = json::Json();
                            expected.setString(msg, "/error");
                            return expected;
                        })),
        // [routePost]: Success
        TestRouterT(
            routePost,
            routerProduction::JParams(ENVIRONMENT_NAME, POLICY_NAME, FILTER_NAME, PRIORITY),
            success([](auto router)
                    { EXPECT_CALL(*router, postEntry(testing::_)).WillOnce(::testing::Return(std::nullopt)); })),
        // [routeDelete]: Fail
        TestRouterT(routeDelete,
                    routerProduction::JParams(ENVIRONMENT_NAME),
                    failureWPayload(
                        [](auto router) -> json::Json
                        {
                            base::OptError error = base::Error {"Name cannot be empty"};
                            EXPECT_CALL(*router, deleteEntry(testing::_)).WillOnce(::testing::Return(error));
                            auto expected = json::Json();
                            expected.setString(base::getError(error).message, "/error");
                            return expected;
                        })),
        // [routeDelete]: Sucess
        TestRouterT(
            routeDelete,
            routerProduction::JParams(ENVIRONMENT_NAME, false),
            success([](auto router)
                    { EXPECT_CALL(*router, deleteEntry(testing::_)).WillOnce(::testing::Return(std::nullopt)); })),
        // [routeReload]: Fail
        TestRouterT(routeReload,
                    routerProduction::JParams(ENVIRONMENT_NAME),
                    failureWPayload(
                        [](auto router) -> json::Json
                        {
                            base::OptError error = base::Error {"Name cannot be empty"};
                            EXPECT_CALL(*router, reloadEntry(testing::_)).WillOnce(::testing::Return(error));
                            auto expected = json::Json();
                            expected.setString(base::getError(error).message, "/error");
                            return expected;
                        })),
        // [routeReload]: Sucess
        TestRouterT(
            routeReload,
            routerProduction::JParams(ENVIRONMENT_NAME, false),
            success([](auto router)
                    { EXPECT_CALL(*router, reloadEntry(testing::_)).WillOnce(::testing::Return(std::nullopt)); })),
        // [routePatchPriority]: Fail
        TestRouterT(routePatchPriority,
                    routerProduction::JParams(ENVIRONMENT_NAME),
                    failureWPayload(
                        [](auto router) -> json::Json
                        {
                            base::OptError error = base::Error {"Name cannot be empty"};
                            EXPECT_CALL(*router, changeEntryPriority(testing::_, testing::_))
                                .WillOnce(::testing::Return(error));
                            auto expected = json::Json();
                            expected.setString(base::getError(error).message, "/error");
                            return expected;
                        })),
        // [routePatchPriority]: Sucess
        TestRouterT(routePatchPriority,
                    routerProduction::JParams(ENVIRONMENT_NAME, false),
                    success(
                        [](auto router) {
                            EXPECT_CALL(*router, changeEntryPriority(testing::_, testing::_))
                                .WillOnce(::testing::Return(std::nullopt));
                        })),
        // [queuePost]: Fail
        TestRouterT(queuePost,
                    routerProduction::JParams("", "", "", 0, false).event(""),
                    failureWPayload(
                        [](auto router) -> json::Json
                        {
                            base::OptError error = base::Error {"Name cannot be empty"};
                            EXPECT_CALL(*router, postStrEvent(testing::_)).WillOnce(::testing::Return(error));
                            auto expected = json::Json();
                            expected.setString(base::getError(error).message, "/error");
                            return expected;
                        })),
        // [queuePost]: Sucess
        TestRouterT(
            queuePost,
            routerProduction::JParams("", "", "", 0, false).event("Hi! i am an event!"),
            success([](auto router)
                    { EXPECT_CALL(*router, postStrEvent(testing::_)).WillOnce(::testing::Return(std::nullopt)); }))));

class RouterHandlerTestComplement : public ::testing::TestWithParam<TestRouterTComplement>
{
protected:
    std::shared_ptr<MockPolicy> m_policy;
    std::shared_ptr<MockRouterAPI> m_router;

    void SetUp() override
    {
        m_router = std::make_shared<MockRouterAPI>();
        m_policy = std::make_shared<MockPolicy>();
    }

    void TearDown() override
    {
        m_router.reset();
        m_policy.reset();
    }
};

TEST_P(RouterHandlerTestComplement, processRequest)
{
    const auto [getHandlerFn, jparams, expectedFn] = GetParam();

    auto expectedResponse = expectedFn(m_router, m_policy);
    auto request = api::wpRequest::create("router.command", "test", jparams);

    auto response = getHandlerFn(m_router, m_policy)(request);

    if (expectedResponse.data().getString(STATUS_PATH) == STATUS_ERROR)
    {
        EXPECT_STREQ(expectedResponse.data().getString(ERROR_PATH).value().c_str(),
                     response.data().getString(ERROR_PATH).value().c_str());
    }
    else
    {
        if (response.data().getString("/route/policy_sync").has_value())
        {
            EXPECT_STREQ(expectedResponse.data().getString("/policy_sync").value().c_str(),
                         response.data().getString("/route/policy_sync").value().c_str());
        }
        else if (response.data().getArray("/table").has_value())
        {
            EXPECT_STREQ(expectedResponse.data().getString("/policy_sync").value().c_str(),
                         response.data().getArray("/table").value()[0].getString("/policy_sync").value().c_str());
        }
        else
        {
            ASSERT_EQ(expectedResponse.data(), response.data());
        }
    }
}

INSTANTIATE_TEST_SUITE_P(
    HandlerrouterProduction,
    RouterHandlerTestComplement,
    testing::Values(
        // [routePost]: Fail
        TestRouterTComplement(routeGet,
                              routerProduction::JParams(ENVIRONMENT_NAME, false),
                              failureWPayloadComplement(
                                  [](auto router, auto policy) -> json::Json
                                  {
                                      base::OptError error = base::Error {"Name cannot be empty"};
                                      EXPECT_CALL(*router, getEntry(testing::_))
                                          .WillOnce(::testing::Return(error.value()));
                                      auto expected = json::Json();
                                      expected.setString(base::getError(error).message, "/error");
                                      return expected;
                                  })),
        TestRouterTComplement(
            routeGet,
            routerProduction::JParams(ENVIRONMENT_NAME, false),
            succesWPayloadComplement(
                [](auto router, auto policy) -> json::Json
                {
                    router::prod::Entry entry(router::prod::EntryPost {"name", "policy", "filter", 0});
                    EXPECT_CALL(*router, getEntry(testing::_)).WillOnce(::testing::Return(entry));

                    auto error = base::Error {"ERROR"};
                    EXPECT_CALL(*policy, getHash(testing::_)).WillOnce(::testing::Return(error));
                    entry.policySync(router::env::Sync::ERROR);
                    auto res = json::Json(R"({})");
                    res.setString(syncToString(entry.policySync()), "/policy_sync");
                    return res;
                })),
        TestRouterTComplement(
            routeGet,
            routerProduction::JParams(ENVIRONMENT_NAME, false),
            succesWPayloadComplement(
                [](auto router, auto policy) -> json::Json
                {
                    router::prod::Entry entry(router::prod::EntryPost {"name", "policy", "filter", 0});
                    entry.status(router::env::State::ENABLED);
                    EXPECT_CALL(*router, getEntry(testing::_)).WillOnce(::testing::Return(entry));
                    EXPECT_CALL(*policy, getHash(testing::_)).WillOnce(::testing::Return("hash"));
                    entry.policySync(router::env::Sync::OUTDATED);
                    auto res = json::Json(R"({})");
                    res.setString(syncToString(entry.policySync()), "/policy_sync");
                    return res;
                })),
        TestRouterTComplement(
            tableGet,
            routerProduction::JParams(ENVIRONMENT_NAME, false),
            succesWPayloadComplement(
                [](auto router, auto policy) -> json::Json
                {
                    router::prod::Entry entry(router::prod::EntryPost {"name", "policy", "filter", 0});
                    std::list<router::prod::Entry> entries;
                    entries.push_back(entry);
                    // entry.status(router::env::State::ENABLED);
                    EXPECT_CALL(*router, getEntries()).WillRepeatedly(::testing::Return(entries));

                    auto error = base::Error {"ERROR"};
                    EXPECT_CALL(*policy, getHash(testing::_)).WillOnce(::testing::Return(error));
                    entry.policySync(router::env::Sync::ERROR);
                    auto res = json::Json(R"({})");
                    res.setString(syncToString(entry.policySync()), "/policy_sync");
                    return res;
                })),
        TestRouterTComplement(
            tableGet,
            routerProduction::JParams(ENVIRONMENT_NAME, false),
            succesWPayloadComplement(
                [](auto router, auto policy) -> json::Json
                {
                    router::prod::Entry entry(router::prod::EntryPost {"name", "policy", "filter", 0});
                    std::list<router::prod::Entry> entries;
                    entries.push_back(entry);
                    // entry.status(router::env::State::ENABLED);
                    EXPECT_CALL(*router, getEntries()).WillRepeatedly(::testing::Return(entries));

                    auto error = base::Error {"ERROR"};
                    EXPECT_CALL(*policy, getHash(testing::_)).WillOnce(::testing::Return("hash"));
                    entry.policySync(router::env::Sync::OUTDATED);
                    auto res = json::Json(R"({})");
                    res.setString(syncToString(entry.policySync()), "/policy_sync");
                    return res;
                }))));
