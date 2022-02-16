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
    ASSERT_NO_THROW(Registry::registerBuilder("test", builderDummy));
}

TEST(Registry, RegisterDuplicatedBuilder)
{
    ASSERT_THROW(Registry::registerBuilder("test", builderDummy), invalid_argument);
}

TEST(Registry, GetBuilder)
{
    ASSERT_NO_THROW(auto buildB = Registry::getBuilder("test"));
}

TEST(Registry, GetNonExistentBuilder)
{
    ASSERT_THROW(auto buildB = Registry::getBuilder("error"), invalid_argument);
}

TEST(Registry, GetBuilderAndBuilds)
{
    auto buildB = std::get<types::OpBuilder>(Registry::getBuilder("test"));
    types::Observable o = rxcpp::observable<>::empty<types::Event>();
    types::Observable expected = buildB(*Document(R"({"test":1})").get("/test"))(o);
    ASSERT_EQ(o, expected);
}
