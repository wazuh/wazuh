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
    ASSERT_NO_THROW(Registry::registerBuilder("test", c));
}

TEST(Registry, RegisterDuplicatedBuilder)
{
    Registry::BuildDocument b = build;
    Registry::BuildType c = b;
    ASSERT_THROW(Registry::registerBuilder("test", c), invalid_argument);
}

TEST(Registry, GetBuilder)
{
    Registry::BuildDocument b = build;
    Registry::BuildType c = b;
    ASSERT_NO_THROW(auto buildB = Registry::getBuilder("test"));
}

TEST(Registry, GetNonExistentBuilder)
{
    ASSERT_THROW(auto buildB = Registry::getBuilder("error"), invalid_argument);
}

TEST(Registry, GetBuilderAndBuilds)
{
    auto buildB = std::get<Registry::BuildDocument>(Registry::getBuilder("test"));
    Registry::Obs_t o = rxcpp::observable<>::empty<Registry::Event_t>();
    Registry::Obs_t expected = buildB(json::Document(R"({})"))(o);
    ASSERT_EQ(o, expected);
}
