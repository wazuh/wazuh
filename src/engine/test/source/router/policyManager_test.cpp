#include <router/policyManager.hpp>

#include <string>

#include <gtest/gtest.h>

#include "parseEvent.hpp"
#include "register.hpp"

#include "testAuxiliar/routerAuxiliarFunctions.hpp"

TEST(PolicyManager, instance_ok)
{
    auto builder = aux::getFakeBuilder();
    ASSERT_NO_THROW(router::PolicyManager(builder, 1));
}

TEST(PolicyManager, instance_fail_null_builder)
{
    try
    {
        router::PolicyManager(nullptr, 1);
        FAIL();
    }
    catch (const std::runtime_error& e)
    {
        ASSERT_STREQ(e.what(), "PolicyManager: Builder cannot be null");
    }
    catch (...)
    {
        FAIL();
    }
}

TEST(PolicyManager, zero_instances)
{
    auto builder = aux::getFakeBuilder();
    try
    {
        router::PolicyManager(builder, 0);
        FAIL();
    }
    catch (const std::runtime_error& e)
    {
        ASSERT_STREQ(e.what(), "PolicyManager: Number of instances of the policy cannot be 0");
    }
    catch (...)
    {
        FAIL();
    }
}

TEST(PolicyManager, policyFlow)
{
    auto builder = aux::getFakeBuilder();
    auto numOfInstances = 10;

    // Instance
    auto manager = router::PolicyManager(builder, numOfInstances);

    for (std::size_t i = 0; i < numOfInstances; ++i)
    {
        // Add policy
        auto err = manager.addPolicy("policy/env_1/0");
        ASSERT_FALSE(err.has_value()) << err.value().message;

        err = manager.addPolicy("policy/env_2/0");
        ASSERT_FALSE(err.has_value()) << err.value().message;

        err = manager.addPolicy("policy/env_3/0");
        ASSERT_FALSE(err.has_value()) << err.value().message;


        // Create event to process
        auto pathDeco = json::Json::formatJsonPath("~decoder");

        auto e1 = base::parseEvent::parseOssecEvent(aux::sampleEventsStr[0]);
        ASSERT_FALSE(e1->exists(pathDeco));
        auto e2 = base::parseEvent::parseOssecEvent(aux::sampleEventsStr[1]);
        ASSERT_FALSE(e2->exists(pathDeco));
        auto e3 = base::parseEvent::parseOssecEvent(aux::sampleEventsStr[2]);
        ASSERT_FALSE(e3->exists(pathDeco));

        // Process event
        err = manager.forwardEvent("policy/env_1/0", i, e1);
        ASSERT_FALSE(err.has_value()) << err.value().message;
        ASSERT_TRUE(e1->exists(pathDeco) && e1->isString(pathDeco));
        ASSERT_STREQ(e1->getString(pathDeco).value().c_str(), "deco_1");

        err = manager.forwardEvent("policy/env_2/0", i, e2);
        ASSERT_FALSE(err.has_value()) << err.value().message;
        ASSERT_TRUE(e2->exists(pathDeco) && e2->isString(pathDeco));
        ASSERT_STREQ(e2->getString(pathDeco).value().c_str(), "deco_2");

        err = manager.forwardEvent("policy/env_3/0", i, e3);
        ASSERT_FALSE(err.has_value()) << err.value().message;
        ASSERT_TRUE(e3->exists(pathDeco) && e3->isString(pathDeco));
        ASSERT_STREQ(e3->getString(pathDeco).value().c_str(), "deco_3");

        // Delete policy
        err = manager.deletePolicy("policy/env_1/0");
        ASSERT_FALSE(err.has_value()) << err.value().message;

        err = manager.forwardEvent("policy/env_1/0", i, e1);
        ASSERT_TRUE(err.has_value());
        ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/env_1/0' does not exist");

        err = manager.deletePolicy("policy/env_2/0");
        ASSERT_FALSE(err.has_value()) << err.value().message;// Process event

        err = manager.forwardEvent("policy/env_2/0", i, e2);
        ASSERT_TRUE(err.has_value());
        ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/env_2/0' does not exist");

        err = manager.deletePolicy("policy/env_3/0");
        ASSERT_FALSE(err.has_value()) << err.value().message;

        err = manager.forwardEvent("policy/env_3/0", i, e3);
        ASSERT_TRUE(err.has_value());
        ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/env_3/0' does not exist");

    }
}

TEST(PolicyManager, addPolicy_fail)
{
    auto builder = aux::getFakeBuilder();
    auto manager = router::PolicyManager(builder, 1);
    auto err = manager.addPolicy("invalid_env");
    ASSERT_TRUE(err.has_value());
}

TEST(PolicyManager, add_list_del_policy)
{
    auto builder = aux::getFakeBuilder();
    auto manager = router::PolicyManager(builder, 1);
    auto err = manager.addPolicy("policy/env_1/0");
    ASSERT_FALSE(err.has_value()) << err.value().message;

    auto envs = manager.listPolicys();
    ASSERT_EQ(envs.size(), 1);
    ASSERT_STREQ(envs[0].c_str(), "policy/env_1/0");

    err = manager.addPolicy("policy/env_1/0");
    ASSERT_TRUE(err.has_value());
    ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/env_1/0' already exists");

    envs = manager.listPolicys();
    ASSERT_EQ(envs.size(), 1);
    ASSERT_STREQ(envs[0].c_str(), "policy/env_1/0");

    err = manager.deletePolicy("policy/env_1/0");
    ASSERT_FALSE(err.has_value()) << err.value().message;

    envs = manager.listPolicys();
    ASSERT_EQ(envs.size(), 0);

    err = manager.deletePolicy("policy/env_1/0");
    ASSERT_TRUE(err.has_value());
    ASSERT_STREQ(err.value().message.c_str(), "Policy 'policy/env_1/0' does not exist");

    err = manager.addPolicy("policy/env_1/0");
    ASSERT_FALSE(err.has_value()) << err.value().message;

    err = manager.addPolicy("policy/env_2/0");
    ASSERT_FALSE(err.has_value()) << err.value().message;

    err = manager.addPolicy("policy/env_3/0");
    ASSERT_FALSE(err.has_value()) << err.value().message;

    envs = manager.listPolicys();
    ASSERT_EQ(envs.size(), 3);
    std::sort(envs.begin(), envs.end());
    ASSERT_STREQ(envs[0].c_str(), "policy/env_1/0");
    ASSERT_STREQ(envs[1].c_str(), "policy/env_2/0");
    ASSERT_STREQ(envs[2].c_str(), "policy/env_3/0");
}
