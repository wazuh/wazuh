#include <gtest/gtest.h>

#include "builder/register.hpp"
#include "builder/registry.hpp"

using namespace builder::internals;

class RegisterTest : public ::testing::Test
{
protected:
    void TearDown() override { Registry::clear(); }
};

TEST_F(RegisterTest, AllBuildersRegistered)
{
    ASSERT_NO_THROW(registerBuilders());

    // Check all builders have been registered
    ASSERT_NO_THROW(Registry::getBuilder("operation.map"));
    ASSERT_NO_THROW(Registry::getBuilder("operation.condition"));

    ASSERT_NO_THROW(Registry::getBuilder("stage.check"));
    ASSERT_NO_THROW(Registry::getBuilder("stage.allow"));
    ASSERT_NO_THROW(Registry::getBuilder("stage.map"));
    ASSERT_NO_THROW(Registry::getBuilder("stage.normalize"));

    ASSERT_NO_THROW(Registry::getBuilder("stage.parse"));
    ASSERT_NO_THROW(Registry::getBuilder("parser.logql"));

    ASSERT_NO_THROW(Registry::getBuilder("stage.outputs"));
    ASSERT_NO_THROW(Registry::getBuilder("output.file"));

    ASSERT_NO_THROW(Registry::getBuilder("helper.kvdb_get"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.kvdb_get_merge"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.kvdb_match"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.kvdb_not_match"));

    ASSERT_NO_THROW(Registry::getBuilder("helper.exists"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.not_exists"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_eq"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_ne"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_gt"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_ge"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_lt"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.i_le"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_eq"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_ne"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_gt"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_ge"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_lt"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_le"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.r_match"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.r_not_match"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.ip_cidr"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_contains"));

    ASSERT_NO_THROW(Registry::getBuilder("helper.i_calc"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_up"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_lo"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_trim"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.r_ext"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_append"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.s_to_array"));
    ASSERT_NO_THROW(Registry::getBuilder("helper.merge"));
}
