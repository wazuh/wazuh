#include <gtest/gtest.h>

#include <builder/allowedFields.hpp>

using namespace builder;

TEST(AllowedFieldsTest, DefaultConstructor)
{
    ASSERT_NO_THROW(AllowedFields {});
}

TEST(AllowedFieldsTest, Constructor)
{
    json::Json definition {
        R"({
        "name": "schema/allowed-fields/0",
        "allowed_fields": {
            "decoder": ["field1", "field2"],
            "rule": ["field1", "field2"],
            "filter": ["field1", "field2"],
            "output": ["field1", "field2"]
        }
        })"};

    ASSERT_NO_THROW(AllowedFields {definition});
}

TEST(AllowedFieldsTest, ConstructorNotObject)
{
    json::Json definition;
    definition.setArray();
    ASSERT_THROW(AllowedFields {definition}, std::runtime_error);
}

TEST(AllowedFieldsTest, ConstructorMissingName)
{
    json::Json definition {
        R"({
        "allowed_fields": {
            "decoder": ["field1", "field2"],
            "rule": ["field1", "field2"],
            "filter": ["field1", "field2"],
            "output": ["field1", "field2"]
        }
        })"};

    ASSERT_THROW(AllowedFields {definition}, std::runtime_error);
}

TEST(AllowedFieldsTest, ConstructorNotAllowedFieldsObject)
{
    json::Json definition1 {
        R"({
        "name": "schema/allowed-fields/0",
        "allowed_fields": "decoder"
        })"};
    json::Json definition2 {
        R"({
        "name": "schema/allowed-fields/0"
    })"};

    ASSERT_THROW(AllowedFields {definition1}, std::runtime_error);
    ASSERT_THROW(AllowedFields {definition2}, std::runtime_error);
}

TEST(AllowedFieldsTest, ConstructorNotFieldArray)
{
    json::Json definition1 {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "decoder": "field1"
            }
        })"};
    json::Json definition2 {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "decoder": ["field1"],
                "rule": "field1"
            }
        })"};

    ASSERT_THROW(AllowedFields {definition1}, std::runtime_error);
    ASSERT_THROW(AllowedFields {definition2}, std::runtime_error);
}

TEST(AllowedFieldsTest, ConstructorNotFieldString)
{
    json::Json definition1 {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "decoder": [1]
            }
        })"};
    json::Json definition2 {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "decoder": ["field1"],
                "rule": [1]
            }
        })"};

    ASSERT_THROW(AllowedFields {definition1}, std::runtime_error);
    ASSERT_THROW(AllowedFields {definition2}, std::runtime_error);
}

TEST(AllowedFieldsTest, ConstructorUnknownAsset)
{
    json::Json definition1 {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "unknown": ["field1"]
            }
        })"};

    json::Json definition2 {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "decoder": ["field1"],
                "unknown": ["field1"]
            }
        })"};

    ASSERT_THROW(AllowedFields {definition1}, std::runtime_error);
    ASSERT_THROW(AllowedFields {definition2}, std::runtime_error);
}

TEST(AllowedFieldsTest, Check)
{
    json::Json definition {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "decoder": ["field1", "field2"],
                "rule": ["field1", "field2"],
                "filter": ["field1", "field2"],
                "output": ["field1", "field2"]
            }
        })"};

    AllowedFields allowedFields {definition};

    auto fields = std::vector<std::string> {"field1", "field2"};
    for (const auto& field : fields)
    {
        ASSERT_TRUE(allowedFields.check("decoder", field));
        ASSERT_TRUE(allowedFields.check("rule", field));
        ASSERT_TRUE(allowedFields.check("filter", field));
        ASSERT_TRUE(allowedFields.check("output", field));
    }
}

TEST(AllowedFieldsTest, CheckUnknownAsset)
{
    json::Json definition {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "decoder": ["field1", "field2"],
                "rule": ["field1", "field2"],
                "filter": ["field1", "field2"],
                "output": ["field1", "field2"]
            }
        })"};

    AllowedFields allowedFields {definition};

    ASSERT_TRUE(allowedFields.check("unknown", "field1"));
}

TEST(AllowedFieldsTest, CheckNotAllowed)
{
    json::Json definition {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "decoder": ["field1", "field2"],
                "rule": ["field1", "field2"],
                "filter": ["field1", "field2"],
                "output": ["field1", "field2"]
            }
        })"};

    AllowedFields allowedFields {definition};

    ASSERT_FALSE(allowedFields.check("decoder", "field3"));
    ASSERT_FALSE(allowedFields.check("rule", "field3"));
    ASSERT_FALSE(allowedFields.check("filter", "field3"));
    ASSERT_FALSE(allowedFields.check("output", "field3"));
}

TEST(AllowedFieldsTest, CheckRootField)
{
    DotPath rootPath {"."};
    json::Json definition {
        R"({
            "name": "schema/allowed-fields/0",
            "allowed_fields": {
                "decoder": ["field1", "field2"],
                "rule": ["field1", "field2"],
                "filter": ["field1", "field2"],
                "output": ["field1", "field2"]
            }
        })"};

    AllowedFields allowedFields {definition};

    ASSERT_TRUE(allowedFields.check("decoder", rootPath));
    ASSERT_TRUE(allowedFields.check("rule", rootPath));
    ASSERT_TRUE(allowedFields.check("filter", rootPath));
    ASSERT_TRUE(allowedFields.check("output", rootPath));

    ASSERT_TRUE(allowedFields.check("decoder", DotPath::append(rootPath, "field1")));
    ASSERT_TRUE(allowedFields.check("rule", DotPath::append(rootPath, "field1")));
    ASSERT_TRUE(allowedFields.check("filter", DotPath::append(rootPath, "field1")));
    ASSERT_TRUE(allowedFields.check("output", DotPath::append(rootPath, "field1")));

    ASSERT_FALSE(allowedFields.check("decoder", DotPath::append(rootPath, "field3")));
    ASSERT_FALSE(allowedFields.check("rule", DotPath::append(rootPath, "field3")));
    ASSERT_FALSE(allowedFields.check("filter", DotPath::append(rootPath, "field3")));
    ASSERT_FALSE(allowedFields.check("output", DotPath::append(rootPath, "field3")));
}
