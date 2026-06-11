#include <gtest/gtest.h>

#include <builder/allowedFields.hpp>
#include <fmt/format.h>

using namespace builder;

namespace
{
json::Json makeDefinition(std::string_view fields)
{
    return json::Json {fmt::format(
        R"({{
            "name": "schema/allowed-fields/0",
            "decoder_unmodifiable_fields": {}
        }})",
        fields)};
}
} // namespace

TEST(AllowedFieldsTest, DefaultConstructorNoRestrictions)
{
    AllowedFields allowedFields {};

    ASSERT_TRUE(allowedFields.check("decoder", "agent.name"));
    ASSERT_TRUE(allowedFields.check("filter", "agent.name"));
    ASSERT_TRUE(allowedFields.check("output", "agent.name"));
}

TEST(AllowedFieldsTest, Constructor)
{
    ASSERT_NO_THROW(AllowedFields {makeDefinition(R"(["agent.name", "event.original"])")});
}

TEST(AllowedFieldsTest, ConstructorNotObject)
{
    json::Json definition;
    definition.setArray();
    ASSERT_THROW(AllowedFields {definition}, std::runtime_error);
}

TEST(AllowedFieldsTest, ConstructorMissingName)
{
    json::Json definition {R"({"decoder_unmodifiable_fields": ["agent.name"]})"};

    ASSERT_THROW(AllowedFields {definition}, std::runtime_error);
}

TEST(AllowedFieldsTest, ConstructorMissingUnmodifiableFields)
{
    json::Json definition {R"({"name": "schema/allowed-fields/0"})"};

    ASSERT_THROW(AllowedFields {definition}, std::runtime_error);
}

TEST(AllowedFieldsTest, ConstructorUnmodifiableFieldsNotArray)
{
    json::Json definition {
        R"({
            "name": "schema/allowed-fields/0",
            "decoder_unmodifiable_fields": "agent.name"
        })"};

    ASSERT_THROW(AllowedFields {definition}, std::runtime_error);
}

TEST(AllowedFieldsTest, ConstructorUnmodifiableFieldNotString)
{
    json::Json definition {
        R"({
            "name": "schema/allowed-fields/0",
            "decoder_unmodifiable_fields": ["agent.name", 1]
        })"};

    ASSERT_THROW(AllowedFields {definition}, std::runtime_error);
}

TEST(AllowedFieldsTest, DecoderBlockedExact)
{
    AllowedFields allowedFields {makeDefinition(R"(["agent.name", "event.original"])")};

    ASSERT_FALSE(allowedFields.check("decoder", "agent.name"));
    ASSERT_FALSE(allowedFields.check("decoder", "event.original"));
}

TEST(AllowedFieldsTest, DecoderBlockedByPrefix)
{
    AllowedFields allowedFields {makeDefinition(R"(["wazuh.integration"])")};

    ASSERT_FALSE(allowedFields.check("decoder", "wazuh.integration.name"));
    ASSERT_FALSE(allowedFields.check("decoder", "wazuh.integration.category"));
}

TEST(AllowedFieldsTest, PrefixDoesNotMatchPartialFieldName)
{
    AllowedFields allowedFields {makeDefinition(R"(["wazuh.integration"])")};

    ASSERT_TRUE(allowedFields.check("decoder", "wazuh.integration_extra.name"));
}

TEST(AllowedFieldsTest, DecoderAllowedNonRestricted)
{
    AllowedFields allowedFields {makeDefinition(R"(["agent.name", "event.original"])")};

    ASSERT_TRUE(allowedFields.check("decoder", "http.status"));
}

TEST(AllowedFieldsTest, NonDecoderAlwaysAllowed)
{
    AllowedFields allowedFields {makeDefinition(R"(["agent.name", "event.original"])")};

    ASSERT_TRUE(allowedFields.check("filter", "agent.name"));
    ASSERT_TRUE(allowedFields.check("output", "event.original"));
    ASSERT_TRUE(allowedFields.check("unknown", "agent.name"));
}

TEST(AllowedFieldsTest, RootAlwaysAllowed)
{
    AllowedFields allowedFields {makeDefinition(R"(["agent.name", "event.original"])")};
    DotPath rootPath {"."};

    ASSERT_TRUE(allowedFields.check("decoder", rootPath));
    ASSERT_TRUE(allowedFields.check("filter", rootPath));
    ASSERT_TRUE(allowedFields.check("output", rootPath));
}

TEST(AllowedFieldsTest, EmptyListNoRestrictions)
{
    AllowedFields allowedFields {makeDefinition(R"([])")};

    ASSERT_TRUE(allowedFields.check("decoder", "agent.name"));
    ASSERT_TRUE(allowedFields.check("decoder", "event.original"));
}
