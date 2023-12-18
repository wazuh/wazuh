#include <api/test/sessionManager.hpp>
#include <gtest/gtest.h>


using namespace api::sessionManager;

const auto& SESSION_NAME {"sessionDummy"};
const auto& POLICY_NAME {"policyDummy"};
const auto& FILTER_NAME {"filterDummy"};
const auto& ROUTE_NAME {"routerDummy"};
const auto& SESSION_DESCRIPTION {"this a dummy session"};
const auto& SESSION_LIFESPAM {600};

class SessionManagerTest : public ::testing::Test
{
    void SetUp() override { initLogging(); }
};

TEST_F(SessionManagerTest, GetNewSessionIDTest)
{
    // Act
    auto sessionManager = SessionManager();

    EXPECT_EQ(sessionManager.getNewSessionID(), 1);
    sessionManager.getNewSessionID();
    EXPECT_EQ(sessionManager.getNewSessionID(), 3);
    sessionManager.getNewSessionID();
    EXPECT_EQ(sessionManager.getNewSessionID(), 5);
    sessionManager.getNewSessionID();
    EXPECT_EQ(sessionManager.getNewSessionID(), 7);
}

TEST_F(SessionManagerTest, ListSessions)
{
    auto sessionManager = std::make_shared<SessionManager>();
    ASSERT_NE(sessionManager, nullptr) << "SessionManager instance is null";

    constexpr auto numSessions {3};
    for (int i = 1; i <= numSessions; i++)
    {
        const auto& currentSessionName = SESSION_NAME + std::to_string(i);
        const auto& currentPolicyName = POLICY_NAME + std::to_string(i);
        const auto& currentFilterName = FILTER_NAME + std::to_string(i);
        const auto& currentRouteName = ROUTE_NAME + std::to_string(i);

        const auto createSession = sessionManager->createSession(currentSessionName,
                                                                 currentPolicyName,
                                                                 currentFilterName,
                                                                 currentRouteName,
                                                                 sessionManager->getNewSessionID());
        ASSERT_FALSE(createSession.has_value());
    }

    auto i {numSessions};
    for (const auto& session : sessionManager->getSessionsList())
    {
        const auto& expectedSessionName = SESSION_NAME + std::to_string(i);
        ASSERT_STREQ(expectedSessionName.c_str(), session.c_str());
        i--;
    }

    sessionManager->deleteSessions(true);
}

TEST_F(SessionManagerTest, GetSession)
{
    auto sessionManager = std::make_shared<SessionManager>();
    ASSERT_NE(sessionManager, nullptr) << "SessionManager instance is null";

    const uint32_t sessionID = sessionManager->getNewSessionID();

    const auto createSession = sessionManager->createSession(
        SESSION_NAME, POLICY_NAME, FILTER_NAME, ROUTE_NAME, sessionID, SESSION_LIFESPAM, SESSION_DESCRIPTION);
    ASSERT_FALSE(createSession.has_value());

    auto session = sessionManager->getSession(SESSION_NAME);
    ASSERT_TRUE(session.has_value());

    ASSERT_EQ(session.value().getLifespan(), SESSION_LIFESPAM);
    ASSERT_EQ(session.value().getSessionID(), sessionID);
    ASSERT_STREQ(session.value().getDescription().c_str(), SESSION_DESCRIPTION);
    ASSERT_STREQ(session.value().getFilterName().c_str(), FILTER_NAME);
    ASSERT_STREQ(session.value().getPolicyName().c_str(), POLICY_NAME);
    ASSERT_STREQ(session.value().getRouteName().c_str(), ROUTE_NAME);
    ASSERT_STREQ(session.value().getSessionName().c_str(), SESSION_NAME);

    auto sessionNotFound = sessionManager->getSession(POLICY_NAME);
    ASSERT_FALSE(sessionNotFound.has_value());

    sessionManager->deleteSessions(true);
}

TEST_F(SessionManagerTest, DeleteSessions)
{
    auto sessionManager = std::make_shared<SessionManager>();
    ASSERT_NE(sessionManager, nullptr) << "SessionManager instance is null";

    constexpr auto numSessions {3};
    for (auto i = 0; i < numSessions; i++)
    {
        const auto& currentSessionName = SESSION_NAME + std::to_string(i);
        const auto& currentPolicyName = POLICY_NAME + std::to_string(i);
        const auto& currentFilterName = FILTER_NAME + std::to_string(i);
        const auto& currentRouteName = ROUTE_NAME + std::to_string(i);

        const auto createSession = sessionManager->createSession(currentSessionName,
                                                                 currentPolicyName,
                                                                 currentFilterName,
                                                                 currentRouteName,
                                                                 sessionManager->getNewSessionID());
        ASSERT_FALSE(createSession.has_value());
    }

    for (auto i = 0; i < numSessions; i++)
    {
        const auto& expectedSessionName = SESSION_NAME + std::to_string(i);
        ASSERT_TRUE(sessionManager->deleteSessions(false, expectedSessionName));
    }

    ASSERT_TRUE(sessionManager->getSessionsList().empty());

    const auto createSession = sessionManager->createSession(
        SESSION_NAME, POLICY_NAME, FILTER_NAME, ROUTE_NAME, sessionManager->getNewSessionID());
    ASSERT_FALSE(sessionManager->getSessionsList().empty());

    ASSERT_TRUE(sessionManager->deleteSessions(true));
    ASSERT_TRUE(sessionManager->getSessionsList().empty());
}

class SessionManagerParameterizedTest
    : public ::testing::TestWithParam<std::tuple<std::string, std::string, std::string, std::string, std::string>>
{
    void SetUp() override { initLogging(); }
};

TEST_P(SessionManagerParameterizedTest, CreateSession)
{
    auto [sessionNameParameter, policyNameParameter, filterNameParameter, routeNameParameter, output] = GetParam();

    auto sessionManager = std::make_shared<SessionManager>();
    ASSERT_NE(sessionManager, nullptr) << "SessionManager instance is null";

    const auto createSessionWithoutError = sessionManager->createSession(
        SESSION_NAME, POLICY_NAME, FILTER_NAME, ROUTE_NAME, sessionManager->getNewSessionID());
    ASSERT_FALSE(createSessionWithoutError.has_value());

    const auto createSessionWithError = sessionManager->createSession(sessionNameParameter,
                                                                      policyNameParameter,
                                                                      filterNameParameter,
                                                                      routeNameParameter,
                                                                      sessionManager->getNewSessionID());
    ASSERT_TRUE(createSessionWithError.has_value());
    ASSERT_STREQ(output.c_str(), createSessionWithError.value().message.c_str());

    sessionManager->deleteSessions(true);
}

INSTANTIATE_TEST_SUITE_P(
    CreateSession,
    SessionManagerParameterizedTest,
    ::testing::Values(
        std::make_tuple(SESSION_NAME,
                        "policy1",
                        "filter1",
                        "route1",
                        fmt::format("Session name '{}' already exists", SESSION_NAME)),
        std::make_tuple("session1",
                        POLICY_NAME,
                        "filter1",
                        "route1",
                        fmt::format("Policy '{}' is already assigned to a route '{}'", POLICY_NAME, ROUTE_NAME)),
        std::make_tuple("session1",
                        "policy1",
                        FILTER_NAME,
                        "route1",
                        fmt::format("Filter '{}' is already assigned to a route '{}'", FILTER_NAME, ROUTE_NAME)),
        std::make_tuple(
            "session1", "policy1", "filter1", ROUTE_NAME, fmt::format("Route name '{}' already exists", ROUTE_NAME))));
