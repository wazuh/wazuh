#include <gtest/gtest.h>
#include <json.hpp>
#include <rxcpp/rx.hpp>
#include <string>

#include "registry.hpp"

#include "testUtils.hpp"

using namespace std;

Lifter builderDummy(const Document & t)
{
    return [](Observable o) { return o; };
}

TEST(Registry, RegisterBuilder)
{
    AssetBuilder b = builderDummy;
    BuilderVariant c = b;
    ASSERT_NO_THROW(Registry::registerBuilder("test", c));
}

TEST(Registry, RegisterDuplicatedBuilder)
{
    types::AssetBuilder b = builderDummy;
    types::BuilderVariant c = b;
    ASSERT_THROW(Registry::registerBuilder("test", c), invalid_argument);
}

TEST(Registry, GetBuilder)
{
    types::AssetBuilder b = builderDummy;
    types::BuilderVariant c = b;
    ASSERT_NO_THROW(auto buildB = Registry::getBuilder("test"));
}

TEST(Registry, GetNonExistentBuilder)
{
    ASSERT_THROW(auto buildB = Registry::getBuilder("error"), invalid_argument);
}

TEST(Registry, GetBuilderAndBuilds)
{
    auto buildB = std::get<types::AssetBuilder>(Registry::getBuilder("test"));
    types::Observable o = rxcpp::observable<>::empty<types::Event>();
    types::Observable expected = buildB(json::Document(R"({})"))(o);
    ASSERT_EQ(o, expected);
}
