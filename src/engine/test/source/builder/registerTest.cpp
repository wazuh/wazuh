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
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_le"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_lt"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_ge"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_gt"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_eq"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_ne"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_up"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_lo"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_trim"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_le"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_lt"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_ge"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_gt"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_eq"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_ne"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_calc"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.r_match"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.r_not_match"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.r_ext"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.ip_cidr"));
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
