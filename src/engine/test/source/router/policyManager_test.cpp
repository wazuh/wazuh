#include <router/policyManager.hpp>

#include <string>

#include <gtest/gtest.h>

#include "parseEvent.hpp"

#include "routerAuxiliarFunctions.hpp"
#include <testsCommon.hpp>

constexpr auto POLICY_1 = "policy/pol_1/0";
constexpr auto POLICY_2 = "policy/pol_2/0";
constexpr auto POLICY_3 = "policy/pol_3/0";

class PolicyManagerTest
    : public ::testing::Test
    , public MockDeps
{
protected:
    void SetUp() override
    {
        initLogging();
        init();
    }

    void TearDown() override {};
};

TEST_F(PolicyManagerTest, instance_ok)
{
    ASSERT_NO_THROW(router::PolicyManager(m_builder, 1));
}

TEST_F(PolicyManagerTest, instance_fail_null_builder)
{
    try
    {
        auto r = router::PolicyManager(nullptr, 1);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        ASSERT_STREQ(e.what(), "PolicyManager: Builder cannot be null");
    }
    catch (...)
    {
        FAIL() << "Expected std::runtime_error";
    }
}

TEST_F(PolicyManagerTest, zero_instances)
{
    try
    {
        auto r = router::PolicyManager(m_builder, 0);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        ASSERT_STREQ(e.what(), "PolicyManager: Number of instances of the policy cannot be 0");
    }
    catch (...)
    {
        FAIL() << "Expected std::runtime_error";
    }
}

TEST_F(PolicyManagerTest, policyFlow)
{
    auto numOfInstances = 10;

    // Instance
    auto manager = router::PolicyManager(m_builder, numOfInstances);

    for (std::size_t i = 0; i < numOfInstances; ++i)
    {
        // Add policy
        expectBuildPolicy(POLICY_1, numOfInstances);
        auto err = manager.addPolicy(POLICY_1);
        ASSERT_FALSE(err.has_value()) << err.value().message;

        expectBuildPolicy(POLICY_2, numOfInstances);
        err = manager.addPolicy(POLICY_2);
        ASSERT_FALSE(err.has_value()) << err.value().message;

        expectBuildPolicy(POLICY_3, numOfInstances);
        err = manager.addPolicy(POLICY_3);
        ASSERT_FALSE(err.has_value()) << err.value().message;

        // Create event to process
        auto pathDeco = json::Json::formatJsonPath("~decoder");

        auto e1 = base::parseEvent::parseWazuhEvent(aux::sampleEventsStr[0]);
        ASSERT_FALSE(e1->exists(pathDeco));
        auto e2 = base::parseEvent::parseWazuhEvent(aux::sampleEventsStr[1]);
        ASSERT_FALSE(e2->exists(pathDeco));
        auto e3 = base::parseEvent::parseWazuhEvent(aux::sampleEventsStr[2]);
        ASSERT_FALSE(e3->exists(pathDeco));

        // Process event
        auto tmpEvent = e1;
        err = manager.forwardEvent(POLICY_1, i, std::move(tmpEvent));
        ASSERT_FALSE(err.has_value()) << err.value().message;
        ASSERT_TRUE(e1->exists(pathDeco) && e1->isString(pathDeco));
        ASSERT_STREQ(e1->getString(pathDeco).value().c_str(), "deco_1");

        tmpEvent = e2;
        err = manager.forwardEvent(POLICY_2, i, std::move(tmpEvent));
        ASSERT_FALSE(err.has_value()) << err.value().message;
        ASSERT_TRUE(e2->exists(pathDeco) && e2->isString(pathDeco));
        ASSERT_STREQ(e2->getString(pathDeco).value().c_str(), "deco_2");

        tmpEvent = e3;
        err = manager.forwardEvent(POLICY_3, i, std::move(tmpEvent));
        ASSERT_FALSE(err.has_value()) << err.value().message;
        ASSERT_TRUE(e3->exists(pathDeco) && e3->isString(pathDeco));
        ASSERT_STREQ(e3->getString(pathDeco).value().c_str(), "deco_3");

        // Delete policy
        err = manager.deletePolicy(POLICY_1);
        ASSERT_FALSE(err.has_value()) << err.value().message;

        tmpEvent = e1;
        err = manager.forwardEvent(POLICY_1, i, std::move(tmpEvent));
        ASSERT_TRUE(err.has_value());
        ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/pol_1/0' does not exist");

        err = manager.deletePolicy(POLICY_2);
        ASSERT_FALSE(err.has_value()) << err.value().message; // Process event

        tmpEvent = e2;
        err = manager.forwardEvent(POLICY_2, i, std::move(tmpEvent));
        ASSERT_TRUE(err.has_value());
        ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/pol_2/0' does not exist");

        err = manager.deletePolicy(POLICY_3);
        ASSERT_FALSE(err.has_value()) << err.value().message;

        tmpEvent = e3;
        err = manager.forwardEvent(POLICY_3, i, std::move(tmpEvent));
        ASSERT_TRUE(err.has_value());
        ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/pol_3/0' does not exist");
    }
}

TEST_F(PolicyManagerTest, addPolicy_fail)
{
    auto manager = router::PolicyManager(m_builder, 1);
    auto err = manager.addPolicy("invalid_env");
    ASSERT_TRUE(err.has_value());
}

TEST_F(PolicyManagerTest, add_list_del_policy)
{
    auto manager = router::PolicyManager(m_builder, 1);
    expectBuildPolicy(POLICY_1);
    auto err = manager.addPolicy(POLICY_1);
    ASSERT_FALSE(err.has_value()) << err.value().message;

    auto policies = manager.listPolicies();
    ASSERT_EQ(policies.size(), 1);
    ASSERT_STREQ(policies[0].c_str(), POLICY_1);

    expectBuildPolicy(POLICY_1);
    err = manager.addPolicy(POLICY_1);
    ASSERT_TRUE(err.has_value());
    ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/pol_1/0' already exists");

    policies = manager.listPolicies();
    ASSERT_EQ(policies.size(), 1);
    ASSERT_STREQ(policies[0].c_str(), POLICY_1);

    err = manager.deletePolicy(POLICY_1);
    ASSERT_FALSE(err.has_value()) << err.value().message;

    policies = manager.listPolicies();
    ASSERT_EQ(policies.size(), 0);

    err = manager.deletePolicy(POLICY_1);
    ASSERT_TRUE(err.has_value());
    ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/pol_1/0' does not exist");

    expectBuildPolicy(POLICY_1);
    err = manager.addPolicy(POLICY_1);
    ASSERT_FALSE(err.has_value()) << err.value().message;

    expectBuildPolicy(POLICY_2);
    err = manager.addPolicy(POLICY_2);
    ASSERT_FALSE(err.has_value()) << err.value().message;

    expectBuildPolicy(POLICY_3);
    err = manager.addPolicy(POLICY_3);
    ASSERT_FALSE(err.has_value()) << err.value().message;

    policies = manager.listPolicies();
    ASSERT_EQ(policies.size(), 3);
    std::sort(policies.begin(), policies.end());
    ASSERT_STREQ(policies[0].c_str(), POLICY_1);
    ASSERT_STREQ(policies[1].c_str(), POLICY_2);
    ASSERT_STREQ(policies[2].c_str(), POLICY_3);
}
