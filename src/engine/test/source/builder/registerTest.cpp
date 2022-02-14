#include <gtest/gtest.h>

#include "register.hpp"
#include "registry.hpp"

using namespace builder::internals;

TEST(Register, AllBuildersRegistered)
{
    ASSERT_NO_THROW(registerBuilders());

    // Check all builders have been registered
    ASSERT_NO_THROW(Registry::getBuilder("condition.value"));
    ASSERT_NO_THROW(Registry::getBuilder("condition"));
    ASSERT_NO_THROW(Registry::getBuilder("condition.reference"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.exists"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.not_exists"));
    ASSERT_NO_THROW(Registry::getBuilder("map"));
    ASSERT_NO_THROW(Registry::getBuilder("map.value"));
    ASSERT_NO_THROW(Registry::getBuilder("map.reference"));
    ASSERT_NO_THROW(Registry::getBuilder("check"));
    ASSERT_NO_THROW(Registry::getBuilder("normalize"));
    ASSERT_NO_THROW(Registry::getBuilder("outputs"));
    ASSERT_NO_THROW(Registry::getBuilder("combinator.chain"));
    ASSERT_NO_THROW(Registry::getBuilder("combinator.broadcast"));
    ASSERT_NO_THROW(Registry::getBuilder("file"));
    ASSERT_NO_THROW(Registry::getBuilder("decoder"));
    ASSERT_NO_THROW(Registry::getBuilder("rule"));
    ASSERT_NO_THROW(Registry::getBuilder("output"));
    ASSERT_NO_THROW(Registry::getBuilder("filter"));
}
