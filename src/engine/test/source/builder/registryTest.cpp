#include <gtest/gtest.h>
#include <json.hpp>
#include <rxcpp/rx.hpp>
#include <string>

#include "registry.hpp"

#include "test_utils.hpp"

using namespace std;
using namespace builder::internals;

Registry::Op_t build(const json::Document & t)
{
    return [](const Registry::Obs_t & o) { return o; };
}

TEST(Registry, Initializes)
{
    ASSERT_NO_THROW(Registry reg);
}

TEST(Registry, RegisterBuilder)
{
    Registry::BuildDocument b = build;
    Registry::BuildType c = b;
    Registry reg;
    ASSERT_NO_THROW(reg.registerBuilder("test", c));
}

TEST(Registry, RegisterDuplicatedBuilder)
{
    Registry::BuildDocument b = build;
    Registry::BuildType c = b;
    Registry reg;
    reg.registerBuilder("test", c);
    ASSERT_THROW(reg.registerBuilder("test", c), invalid_argument);
}

TEST(Registry, GetBuilder)
{
    Registry::BuildDocument b = build;
    Registry::BuildType c = b;
    Registry reg;
    reg.registerBuilder("test", c);
    ASSERT_NO_THROW(auto buildB = reg.getBuilder("test"));
}

TEST(Registry, GetNonExistentBuilder)
{
    Registry reg;
    ASSERT_THROW(auto buildB = reg.getBuilder("test"), invalid_argument);
}

TEST(Registry, GetBuilderAndBuilds)
{
    Registry::BuildDocument b = build;
    Registry::BuildType c = b;
    Registry reg;
    reg.registerBuilder("test", c);
    auto buildB = std::get<Registry::BuildDocument>(reg.getBuilder("test"));
    Registry::Obs_t o = rxcpp::observable<>::empty<Registry::Event_t>();
    Registry::Obs_t expected = buildB(json::Document(R"({})"))(o);
    ASSERT_EQ(o, expected);
}
