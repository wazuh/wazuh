/**
 * @brief Sandbox Test Suite
 */
#include <string>
#include <algorithm>
#include <gtest/gtest.h>
#include <sandbox/sandbox.hpp>
#include <rxcpp/rx.hpp>

using namespace Sandbox;


TEST(SandboxTest, CreateSandboxTest)
{
    auto s = std::make_shared<Sandbox::Sandbox>();
};


TEST(SandboxTest, AddEnvironmentSandboxTest)
{
    auto s = std::make_shared<Sandbox::Sandbox>();
    s->add("MyTestEnv");
};

TEST(SandboxTest, CountEnvironmentsSandboxTest)
{
    auto s = std::make_shared<Sandbox::Sandbox>();

    s->add(std::string("MyTestEnv"));
    EXPECT_EQ(s->len(), std::size_t(1));
};

TEST(SandboxTest, EnableEnvironment)
{
    auto s = std::make_shared<Sandbox::Sandbox>();

    s->add(std::string("MyTestEnv"));
    EXPECT_EQ(s->len(), std::size_t(1));
    s->enable(std::string("MyTestEnv"));
    // ASSERT_EQ(s->isEnabled(std::string("MyTestEnv")), true);
};

TEST(SandboxTest, DisableEnvironment)
{
    auto s = std::make_shared<Sandbox::Sandbox>();

    s->add(std::string("MyTestEnv"));
    EXPECT_EQ(s->len(), std::size_t(1));
    s->enable(std::string("MyTestEnv"));
    
    // ASSERT_EQ(s->isEnabled(std::string("MyTestEnv")), true);
    s->disable(std::string("MyTestEnv"));

};
