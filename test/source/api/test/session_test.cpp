#include <api/test/sessionManager.hpp>
#include <gtest/gtest.h>
#include <testsCommon.hpp>

using namespace api::sessionManager;
const std::string rCommand {"dummy cmd"};
const std::string rOrigin {"Dummy org module"};

const auto& SESSION_NAME {"sessionDummy"};
const auto& POLICY_NAME {"policyDummy"};
const auto& FILTER_NAME {"filterDummy"};
const auto& ROUTE_NAME {"routerDummy"};
const auto& SESSION_DESCRIPTION {"this a dummy session"};
const auto& SESSION_LIFESPAM {600};

class SessionManagerTest : public ::testing::Test
{
    void SetUp() override
    {
        initLogging();
    }
};

TEST_F(SessionManagerTest, GetInstance)
{
    // Get the instance of SessionManager
    SessionManager& instance1 = SessionManager::getInstance();
    SessionManager& instance2 = SessionManager::getInstance();

    // Verify that both instances refer to the same object
    ASSERT_EQ(&instance1, &instance2) << "Multiple instances of SessionManager created";

    // Verify that the instance is not null
    ASSERT_NE(&instance1, nullptr) << "SessionManager instance is null";
}

TEST_F(SessionManagerTest, GetInstanceMultiThreaded)
{
    constexpr int numThreads = 10;
    std::vector<std::thread> threads;
    std::vector<SessionManager*> instances(numThreads, nullptr);

    // Create multiple threads that call getInstance
    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back([&instances, i]() {
            instances[i] = &SessionManager::getInstance();
        });
    }

    // Wait for all threads to finish
    for (auto& thread : threads)
    {
        thread.join();
    }

    // Verify that all instances are the same and not null
    SessionManager* firstInstance = instances[0];
    ASSERT_NE(firstInstance, nullptr) << "SessionManager instance is null";

    for (int i = 1; i < numThreads; ++i)
    {
        ASSERT_EQ(instances[i], firstInstance) << "Multiple instances of SessionManager created";
    }
}

TEST_F(SessionManagerTest, ListSessions)
{
    auto& instance = SessionManager::getInstance();
    ASSERT_NE(&instance, nullptr) << "SessionManager instance is null";

    constexpr auto numSessions {3};
    for (int i = 1; i <= numSessions; i++)
    {
        const auto& currentSessionName = SESSION_NAME + std::to_string(i);
        const auto& currentPolicyName = POLICY_NAME + std::to_string(i);
        const auto& currentFilterName = FILTER_NAME + std::to_string(i);
        const auto& currentRouteName = ROUTE_NAME + std::to_string(i);

        const auto createSession = instance.createSession(currentSessionName, currentPolicyName, currentFilterName, currentRouteName);
        ASSERT_FALSE(createSession.has_value());
    }

    auto i {numSessions};
    for (const auto& session : instance.getSessionsList())
    {
        const auto& expectedSessionName = SESSION_NAME + std::to_string(i);
        ASSERT_STREQ(expectedSessionName.c_str(), session.c_str());
        i--;
    }

    instance.deleteSessions(true);
}

TEST_F(SessionManagerTest, GetSession)
{
    auto& instance = SessionManager::getInstance();
    ASSERT_NE(&instance, nullptr) << "SessionManager instance is null";

    const auto createSession = instance.createSession(SESSION_NAME, POLICY_NAME, FILTER_NAME, ROUTE_NAME, SESSION_LIFESPAM, SESSION_DESCRIPTION);
    ASSERT_FALSE(createSession.has_value());

    auto session = instance.getSession(SESSION_NAME);
    ASSERT_TRUE(session.has_value());

    ASSERT_STREQ(session.value().getSessionName().c_str(), SESSION_NAME);
    ASSERT_STREQ(session.value().getPolicyName().c_str(), POLICY_NAME);
    ASSERT_STREQ(session.value().getFilterName().c_str(), FILTER_NAME);
    ASSERT_STREQ(session.value().getRouteName().c_str(), ROUTE_NAME);
    ASSERT_STREQ(session.value().getDescription().c_str(), SESSION_DESCRIPTION);
    ASSERT_EQ(session.value().getLifespan(), SESSION_LIFESPAM);

    auto sessionNotFound = instance.getSession(POLICY_NAME);
    ASSERT_FALSE(sessionNotFound.has_value());

    instance.deleteSessions(true);
}

TEST_F(SessionManagerTest, DeleteSessions)
{
    auto& instance = SessionManager::getInstance();
    ASSERT_NE(&instance, nullptr) << "SessionManager instance is null";

    constexpr auto numSessions {3};
    for (auto i = 0; i < numSessions; i++)
    {
        const auto& currentSessionName = SESSION_NAME + std::to_string(i);
        const auto& currentPolicyName = POLICY_NAME + std::to_string(i);
        const auto& currentFilterName = FILTER_NAME + std::to_string(i);
        const auto& currentRouteName = ROUTE_NAME + std::to_string(i);

        const auto createSession = instance.createSession(currentSessionName, currentPolicyName, currentFilterName, currentRouteName);
        ASSERT_FALSE(createSession.has_value());
    }

    for (auto i = 0; i < numSessions; i++)
    {
        const auto& expectedSessionName = SESSION_NAME + std::to_string(i);
        ASSERT_TRUE(instance.deleteSessions(false, expectedSessionName));
    }

    ASSERT_TRUE(instance.getSessionsList().empty());

    const auto createSession = instance.createSession(SESSION_NAME, POLICY_NAME, FILTER_NAME, ROUTE_NAME);
    ASSERT_FALSE(instance.getSessionsList().empty());

    ASSERT_TRUE(instance.deleteSessions(true));
    ASSERT_TRUE(instance.getSessionsList().empty());
}

class SessionManagerParameterizedTest : public ::testing::TestWithParam<std::tuple<std::string, std::string, std::string, std::string, std::string>>
{
    void SetUp() override
    {
        initLogging();
    }
};

TEST_P(SessionManagerParameterizedTest, CreateSession)
{
    auto [sessionNameParameter, policyNameParameter, filterNameParameter, routeNameParameter, output] = GetParam();

    auto& instance = SessionManager::getInstance();
    ASSERT_NE(&instance, nullptr) << "SessionManager instance is null";

    const auto createSessionWithoutError = instance.createSession(SESSION_NAME, POLICY_NAME, FILTER_NAME, ROUTE_NAME);
    ASSERT_FALSE(createSessionWithoutError.has_value());

    const auto createSessionWithError = instance.createSession(sessionNameParameter, policyNameParameter, filterNameParameter, routeNameParameter);
    ASSERT_TRUE(createSessionWithError.has_value());
    ASSERT_STREQ(output.c_str(), createSessionWithError.value().message.c_str());

    instance.deleteSessions(true);
}

INSTANTIATE_TEST_SUITE_P(
    CreateSession,
    SessionManagerParameterizedTest,
    ::testing::Values(std::make_tuple(SESSION_NAME, "policy1", "filter1", "route1", fmt::format("Session name '{}' already exists", SESSION_NAME)),
                      std::make_tuple("session1", POLICY_NAME, "filter1", "route1", fmt::format("Policy '{}' is already assigned to a route '{}'", POLICY_NAME, ROUTE_NAME)),
                      std::make_tuple("session1", "policy1", FILTER_NAME, "route1", fmt::format("Filter '{}' is already assigned to a route '{}'", FILTER_NAME, ROUTE_NAME)),
                      std::make_tuple("session1", "policy1", "filter1", ROUTE_NAME, fmt::format("Route name '{}' already exists", ROUTE_NAME))));

