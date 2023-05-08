#include <gtest/gtest.h>

#include <memory>

#include "builder/register.hpp"
#include "builder/registry.hpp"

using namespace builder::internals;

TEST(RegisterTest, AllHelperBuildersRegistered)
{
    auto helperRegistry = std::make_shared<Registry<builder::internals::HelperBuilder>>();
    ASSERT_NO_THROW(registerHelperBuilders(helperRegistry));

    // Check all helper builders have been registered
    ASSERT_NO_THROW(helperRegistry->getBuilder("kvdb_get"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("kvdb_get_merge"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("kvdb_match"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("kvdb_not_match"));

    ASSERT_NO_THROW(helperRegistry->getBuilder("exists"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("not_exists"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("int_equal"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("int_not_equal"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("int_greater"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("int_greater_or_equal"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("int_less"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("int_less_or_equal"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("string_equal"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("string_not_equal"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("string_greater"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("string_greater_or_equal"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("string_less"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("string_less_or_equal"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("regex_match"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("regex_not_match"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("ip_cidr_match"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("array_contains"));

    ASSERT_NO_THROW(helperRegistry->getBuilder("int_calculate"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("upcase"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("downcase"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("trim"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("regex_extract"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("array_append"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("split"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("hex_to_number"));
    ASSERT_NO_THROW(helperRegistry->getBuilder("merge"));
}

TEST(RegisterTest, AllBuildersRegistered)
{
    auto registry = std::make_shared<Registry<builder::internals::Builder>>();
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
}
