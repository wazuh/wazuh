#include <gtest/gtest.h>

#include <memory>

#include "builder/register.hpp"
#include "builder/registry.hpp"

using namespace builder::internals;

TEST(RegisterTest, AllBuildersRegistered)
{
    auto registry = std::make_shared<Registry>();
    ASSERT_NO_THROW(registerBuilders(registry));

    // Check all builders have been registered
    ASSERT_NO_THROW(registry->getBuilder("operation.map"));
    ASSERT_NO_THROW(registry->getBuilder("operation.condition"));

    ASSERT_NO_THROW(registry->getBuilder("stage.check"));
    ASSERT_NO_THROW(registry->getBuilder("stage.allow"));
    ASSERT_NO_THROW(registry->getBuilder("stage.map"));
    ASSERT_NO_THROW(registry->getBuilder("stage.normalize"));

    ASSERT_NO_THROW(registry->getBuilder("stage.parse"));
    ASSERT_NO_THROW(registry->getBuilder("parser.logpar"));

    ASSERT_NO_THROW(registry->getBuilder("stage.outputs"));
    ASSERT_NO_THROW(registry->getBuilder("output.file"));

    ASSERT_NO_THROW(registry->getBuilder("helper.kvdb_get"));
    ASSERT_NO_THROW(registry->getBuilder("helper.kvdb_get_merge"));
    ASSERT_NO_THROW(registry->getBuilder("helper.kvdb_match"));
    ASSERT_NO_THROW(registry->getBuilder("helper.kvdb_not_match"));

    ASSERT_NO_THROW(registry->getBuilder("helper.ef_exists"));
    ASSERT_NO_THROW(registry->getBuilder("helper.ef_not_exists"));
    ASSERT_NO_THROW(registry->getBuilder("helper.i_eq"));
    ASSERT_NO_THROW(registry->getBuilder("helper.i_ne"));
    ASSERT_NO_THROW(registry->getBuilder("helper.i_gt"));
    ASSERT_NO_THROW(registry->getBuilder("helper.i_ge"));
    ASSERT_NO_THROW(registry->getBuilder("helper.i_lt"));
    ASSERT_NO_THROW(registry->getBuilder("helper.i_le"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_eq"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_ne"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_gt"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_ge"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_lt"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_le"));
    ASSERT_NO_THROW(registry->getBuilder("helper.r_match"));
    ASSERT_NO_THROW(registry->getBuilder("helper.r_not_match"));
    ASSERT_NO_THROW(registry->getBuilder("helper.ip_cidr"));
    ASSERT_NO_THROW(registry->getBuilder("helper.a_contains"));

    ASSERT_NO_THROW(registry->getBuilder("helper.i_calc"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_up"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_lo"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_trim"));
    ASSERT_NO_THROW(registry->getBuilder("helper.r_ext"));
    ASSERT_NO_THROW(registry->getBuilder("helper.a_append"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_to_array"));
    ASSERT_NO_THROW(registry->getBuilder("helper.s_hex_to_num"));
    ASSERT_NO_THROW(registry->getBuilder("helper.ef_merge"));
}
