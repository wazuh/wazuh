#include <gtest/gtest.h>
#include <rxcpp/rx.hpp>

#include "registry.hpp"
#include "testUtils.hpp"
#include <json.hpp>

using FakeTrFn = std::function<void(std::string)>;
FakeTrFn tr = [](std::string msg){};

Lifter builderDummy(const Document &t, FakeTrFn tr)
{
    return [](Observable o)
    {
        return o;
    };
}

TEST(Registry_test, RegisterBuilder)
{
    ASSERT_NO_THROW(Registry::registerBuilder("test", builderDummy));
}

TEST(Registry_test, RegisterDuplicatedBuilder)
{
    ASSERT_THROW(Registry::registerBuilder("test", builderDummy),
                 invalid_argument);
}

TEST(Registry_test, GetBuilder)
{
    ASSERT_NO_THROW(auto buildB = Registry::getBuilder("test"));
}

TEST(Registry_test, GetNonExistentBuilder)
{
    ASSERT_THROW(auto buildB = Registry::getBuilder("error"), invalid_argument);
}

TEST(Registry_test, GetBuilderAndBuilds)
{
    auto buildB = std::get<types::OpBuilder>(Registry::getBuilder("test"));
    base::Observable o = rxcpp::observable<>::empty<base::Event>();
    base::Observable expected = buildB(Document(R"({"test":1})").get("/test"), tr)(o);
    ASSERT_EQ(o, expected);
}
