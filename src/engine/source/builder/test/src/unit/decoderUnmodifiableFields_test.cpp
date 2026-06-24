#include <gtest/gtest.h>

#include <builder/decoderUnmodifiableFields.hpp>
#include <fmt/format.h>

using namespace builder;

namespace
{
json::Json makeDefinition(std::string_view fields)
{
    return json::Json {fmt::format(
        R"({{
            "name": "schema/decoder-unmodifiable-fields/0",
            "decoder_unmodifiable_fields": {}
        }})",
        fields)};
}
} // namespace

TEST(DecoderUnmodifiableFieldsTest, DefaultConstructorNoRestrictions)
{
    DecoderUnmodifiableFields decoderUnmodifiableFields {};

    ASSERT_TRUE(decoderUnmodifiableFields.check("decoder", "agent.name"));
    ASSERT_TRUE(decoderUnmodifiableFields.check("filter", "agent.name"));
    ASSERT_TRUE(decoderUnmodifiableFields.check("output", "agent.name"));
}

TEST(DecoderUnmodifiableFieldsTest, Constructor)
{
    ASSERT_NO_THROW(DecoderUnmodifiableFields {makeDefinition(R"(["agent.name", "event.original"])")});
}

TEST(DecoderUnmodifiableFieldsTest, ConstructorNotObject)
{
    json::Json definition;
    definition.setArray();
    ASSERT_THROW(DecoderUnmodifiableFields {definition}, std::runtime_error);
}

TEST(DecoderUnmodifiableFieldsTest, ConstructorMissingName)
{
    json::Json definition {R"({"decoder_unmodifiable_fields": ["agent.name"]})"};

    ASSERT_THROW(DecoderUnmodifiableFields {definition}, std::runtime_error);
}

TEST(DecoderUnmodifiableFieldsTest, ConstructorMissingUnmodifiableFields)
{
    json::Json definition {R"({"name": "schema/decoder-unmodifiable-fields/0"})"};

    ASSERT_THROW(DecoderUnmodifiableFields {definition}, std::runtime_error);
}

TEST(DecoderUnmodifiableFieldsTest, ConstructorUnmodifiableFieldsNotArray)
{
    json::Json definition {
        R"({
            "name": "schema/decoder-unmodifiable-fields/0",
            "decoder_unmodifiable_fields": "agent.name"
        })"};

    ASSERT_THROW(DecoderUnmodifiableFields {definition}, std::runtime_error);
}

TEST(DecoderUnmodifiableFieldsTest, ConstructorUnmodifiableFieldNotString)
{
    json::Json definition {
        R"({
            "name": "schema/decoder-unmodifiable-fields/0",
            "decoder_unmodifiable_fields": ["agent.name", 1]
        })"};

    ASSERT_THROW(DecoderUnmodifiableFields {definition}, std::runtime_error);
}

TEST(DecoderUnmodifiableFieldsTest, DecoderBlockedExact)
{
    DecoderUnmodifiableFields decoderUnmodifiableFields {makeDefinition(R"(["agent.name", "event.original"])")};

    ASSERT_FALSE(decoderUnmodifiableFields.check("decoder", "agent.name"));
    ASSERT_FALSE(decoderUnmodifiableFields.check("decoder", "event.original"));
}

TEST(DecoderUnmodifiableFieldsTest, DecoderBlockedByPrefix)
{
    DecoderUnmodifiableFields decoderUnmodifiableFields {makeDefinition(R"(["wazuh.integration"])")};

    ASSERT_FALSE(decoderUnmodifiableFields.check("decoder", "wazuh.integration.name"));
    ASSERT_FALSE(decoderUnmodifiableFields.check("decoder", "wazuh.integration.category"));
}

TEST(DecoderUnmodifiableFieldsTest, PrefixDoesNotMatchPartialFieldName)
{
    DecoderUnmodifiableFields decoderUnmodifiableFields {makeDefinition(R"(["wazuh.integration"])")};

    ASSERT_TRUE(decoderUnmodifiableFields.check("decoder", "wazuh.integration_extra.name"));
}

TEST(DecoderUnmodifiableFieldsTest, DecoderAllowedNonRestricted)
{
    DecoderUnmodifiableFields decoderUnmodifiableFields {makeDefinition(R"(["agent.name", "event.original"])")};

    ASSERT_TRUE(decoderUnmodifiableFields.check("decoder", "http.status"));
}

TEST(DecoderUnmodifiableFieldsTest, NonDecoderAlwaysAllowed)
{
    DecoderUnmodifiableFields decoderUnmodifiableFields {makeDefinition(R"(["agent.name", "event.original"])")};

    ASSERT_TRUE(decoderUnmodifiableFields.check("filter", "agent.name"));
    ASSERT_TRUE(decoderUnmodifiableFields.check("output", "event.original"));
    ASSERT_TRUE(decoderUnmodifiableFields.check("unknown", "agent.name"));
}

TEST(DecoderUnmodifiableFieldsTest, RootAlwaysAllowed)
{
    DecoderUnmodifiableFields decoderUnmodifiableFields {makeDefinition(R"(["agent.name", "event.original"])")};
    DotPath rootPath {"."};

    ASSERT_TRUE(decoderUnmodifiableFields.check("decoder", rootPath));
    ASSERT_TRUE(decoderUnmodifiableFields.check("filter", rootPath));
    ASSERT_TRUE(decoderUnmodifiableFields.check("output", rootPath));
}

TEST(DecoderUnmodifiableFieldsTest, EmptyListNoRestrictions)
{
    DecoderUnmodifiableFields decoderUnmodifiableFields {makeDefinition(R"([])")};

    ASSERT_TRUE(decoderUnmodifiableFields.check("decoder", "agent.name"));
    ASSERT_TRUE(decoderUnmodifiableFields.check("decoder", "event.original"));
}
