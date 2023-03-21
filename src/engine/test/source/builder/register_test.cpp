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

    ASSERT_NO_THROW(registry->getBuilder("helper.exists"));
    ASSERT_NO_THROW(registry->getBuilder("helper.not_exists"));
    ASSERT_NO_THROW(registry->getBuilder("helper.int_equal"));
    ASSERT_NO_THROW(registry->getBuilder("helper.int_not_equal"));
    ASSERT_NO_THROW(registry->getBuilder("helper.int_greater"));
    ASSERT_NO_THROW(registry->getBuilder("helper.int_greater_or_equal"));
    ASSERT_NO_THROW(registry->getBuilder("helper.int_less"));
    ASSERT_NO_THROW(registry->getBuilder("helper.int_less_or_equal"));
    ASSERT_NO_THROW(registry->getBuilder("helper.string_equal"));
    ASSERT_NO_THROW(registry->getBuilder("helper.string_not_equal"));
    ASSERT_NO_THROW(registry->getBuilder("helper.string_greater"));
    ASSERT_NO_THROW(registry->getBuilder("helper.string_greater_or_equal"));
    ASSERT_NO_THROW(registry->getBuilder("helper.string_less"));
    ASSERT_NO_THROW(registry->getBuilder("helper.string_less_or_equal"));
    ASSERT_NO_THROW(registry->getBuilder("helper.regex_match"));
    ASSERT_NO_THROW(registry->getBuilder("helper.regex_not_match"));
    ASSERT_NO_THROW(registry->getBuilder("helper.ip_cidr_match"));
    ASSERT_NO_THROW(registry->getBuilder("helper.array_contains"));

    ASSERT_NO_THROW(registry->getBuilder("helper.int_calculate"));
    ASSERT_NO_THROW(registry->getBuilder("helper.upcase"));
    ASSERT_NO_THROW(registry->getBuilder("helper.downcase"));
    ASSERT_NO_THROW(registry->getBuilder("helper.trim"));
    ASSERT_NO_THROW(registry->getBuilder("helper.regex_extract"));
    ASSERT_NO_THROW(registry->getBuilder("helper.array_append"));
    ASSERT_NO_THROW(registry->getBuilder("helper.split"));
    ASSERT_NO_THROW(registry->getBuilder("helper.hex_to_number"));
    ASSERT_NO_THROW(registry->getBuilder("helper.merge"));
}
