#include <defs/defs.hpp>
#include <gtest/gtest.h>

class DefsBuildTest : public ::testing::TestWithParam<std::tuple<json::Json, bool>>
{
};

TEST_P(DefsBuildTest, Builds)
{
    auto [definitions, shouldPass] = GetParam();

    if (shouldPass)
    {
        ASSERT_NO_THROW(auto def = defs::Definitions(definitions));
    }
    else
    {
        ASSERT_THROW(auto def = defs::Definitions(definitions), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    Builds,
    DefsBuildTest,
    ::testing::Values(
        // Value test
        std::make_tuple(json::Json(), false),
        std::make_tuple(json::Json(R"([])"), false),
        std::make_tuple(json::Json(R"(["a"])"), false),
        std::make_tuple(json::Json(R"({})"), true),
        std::make_tuple(json::Json(R"({"a": 1})"), true),
        std::make_tuple(json::Json(R"({"a": "1"})"), true),
        std::make_tuple(json::Json(R"({"a": true})"), true),
        std::make_tuple(json::Json(R"({"a": false})"), true),
        std::make_tuple(json::Json(R"({"a": null})"), true),
        std::make_tuple(json::Json(R"({"a": []})"), true),
        std::make_tuple(json::Json(R"({"a": {}})"), true),
        std::make_tuple(json::Json(R"({"a": 1, "b":"1", "c":true, "d":false, "e":null, "f":[], "g":{}})"), true),
        std::make_tuple(json::Json(R"({"$a": 1})"), false),
        // Key test
        std::make_tuple(json::Json(R"({"$invalid": "test"})"), false),
        std::make_tuple(json::Json(R"({"valid_123": "test"})"), true),
        std::make_tuple(json::Json(R"({"_underscore": "test"})"), true),
        std::make_tuple(json::Json(R"({"CamelCase": "test"})"), true)
        // EMD
        ));

class DefsGetTest : public ::testing::TestWithParam<std::tuple<json::Json, std::string, json::Json, bool>>
{
};

TEST_P(DefsGetTest, Gets)
{
    auto [definitions, toGet, expected, shouldPass] = GetParam();
    auto def = defs::Definitions(definitions);
    if (shouldPass)
    {
        ASSERT_EQ(def.get(toGet), expected);
    }
    else
    {
        ASSERT_THROW(def.get(toGet), std::runtime_error);
    }
}

INSTANTIATE_TEST_SUITE_P(
    Gets,
    DefsGetTest,
    ::testing::Values(
        // Basic keys
        std::make_tuple(json::Json(R"({"a": 1})"), "/a", json::Json("1"), true),
        std::make_tuple(json::Json(R"({"a": "1"})"), "/a", json::Json(R"("1")"), true),
        std::make_tuple(json::Json(R"({"a": true})"), "/a", json::Json("true"), true),
        std::make_tuple(json::Json(R"({"a": false})"), "/a", json::Json("false"), true),
        std::make_tuple(json::Json(R"({"a": null})"), "/a", json::Json("null"), true),
        std::make_tuple(json::Json(R"({"a": []})"), "/a", json::Json("[]"), true),
        std::make_tuple(json::Json(R"({"a": {}})"), "/a", json::Json("{}"), true),
        std::make_tuple(json::Json(R"({"a": 1})"), "/b", json::Json(), false),
        // Nested keys
        std::make_tuple(json::Json(R"({"nested": {"key": "value"}})"), "/nested/key", json::Json(R"("value")"), true),
        std::make_tuple(json::Json(R"({"array": [1,2,3]})"), "/array/0", json::Json("1"), true),
        std::make_tuple(
            json::Json(R"({"complex": {"array": [{"id": 123}]}})"), "/complex/array/0/id", json::Json("123"), true)
        // END
        ));

// Test of circular reference detection in definitions
TEST(DefsCircularRefTest, Detects)
{
    auto definitions = json::Json(R"({"a": "$b", "b": "$a"})");
    ASSERT_THROW(auto def = defs::Definitions(definitions), std::runtime_error);

    definitions = json::Json(R"({"a": "$b", "b": "$c", "c": "$a"})");
    ASSERT_THROW(auto def = defs::Definitions(definitions), std::runtime_error);

    definitions = json::Json(R"({"a": "$a"})");
    ASSERT_THROW(auto def = defs::Definitions(definitions), std::runtime_error);

    // New complex circular reference cases
    definitions = json::Json(R"({"a": "prefix $b suffix", "b": "start $a end"})");
    ASSERT_THROW(auto def = defs::Definitions(definitions), std::runtime_error);

    definitions = json::Json(R"({"a": "$b$c", "b": "$c$a", "c": "value"})");
    ASSERT_THROW(auto def = defs::Definitions(definitions), std::runtime_error);

    definitions = json::Json(R"({"path1": "$path2/sub", "path2": "$path1/base"})");
    ASSERT_THROW(auto def = defs::Definitions(definitions), std::runtime_error);
}

// Test contains method
class DefsContainsTest : public ::testing::TestWithParam<std::tuple<json::Json, std::string, bool>>
{
};

TEST_P(DefsContainsTest, Contains)
{
    auto [definitions, name, expected] = GetParam();
    auto def = defs::Definitions(definitions);
    ASSERT_EQ(def.contains(name), expected);
}

INSTANTIATE_TEST_SUITE_P(
    Contains,
    DefsContainsTest,
    ::testing::Values(std::make_tuple(json::Json(R"({"a": "value"})"), "/a", true),
                      std::make_tuple(json::Json(R"({"a": "value"})"), "/b", false),
                      std::make_tuple(json::Json(R"({})"), "/a", false),
                      std::make_tuple(json::Json(R"({"nested": {"key": "value"}})"), "/nested", true),
                      std::make_tuple(json::Json(R"({"nested": {"key": "value"}})"), "/nested/key", true),
                      std::make_tuple(json::Json(R"({"nested": {"key": "value"}})"), "/nested/missing", false),
                      std::make_tuple(json::Json(R"({"array": [1,2,3]})"), "/array", true),
                      std::make_tuple(json::Json(R"({"array": [1,2,3]})"), "/array/0", true),
                      std::make_tuple(json::Json(R"({"array": [1,2,3]})"), "/array/5", false)));

// Test empty definitions object
TEST(DefsEmptyTest, EmptyDefinitions)
{
    auto def = defs::Definitions(json::Json(R"({})"));

    // Should handle replace on empty definitions gracefully
    ASSERT_EQ(def.replace("$nonexistent"), "$nonexistent");
    ASSERT_EQ(def.replace("no variables here"), "no variables here");
    ASSERT_EQ(def.replace(""), "");

    // Should not contain any definitions
    ASSERT_FALSE(def.contains("/anything"));

    // Should throw on get
    ASSERT_THROW(def.get("/missing"), std::runtime_error);
}

// Test default constructor
TEST(DefsDefaultTest, DefaultConstructor)
{
    auto def = defs::Definitions();

    // Should handle replace gracefully with null definitions
    ASSERT_EQ(def.replace("$test"), "$test");
    ASSERT_EQ(def.replace("normal text"), "normal text");

    // Should return false for contains
    ASSERT_FALSE(def.contains("/anything"));
}

class DefsReplaceTest : public ::testing::TestWithParam<std::tuple<json::Json, std::string, std::string>>
{
};

TEST_P(DefsReplaceTest, Replaces)
{
    auto [definitions, input, expected] = GetParam();

    auto def = defs::Definitions(definitions);
    ASSERT_EQ(def.replace(input), expected);
}

INSTANTIATE_TEST_SUITE_P(
    Replaces,
    DefsReplaceTest,
    ::testing::Values(
        // Basic replacements
        std::make_tuple(json::Json(R"({"a": "value"})"), "$a", "value"),
        std::make_tuple(json::Json(R"({"a": 1})"), "$a", "1"),
        std::make_tuple(json::Json(R"({"a": true})"), "$a", "true"),
        std::make_tuple(json::Json(R"({"a": false})"), "$a", "false"),
        std::make_tuple(json::Json(R"({"a": null})"), "$a", "null"),
        std::make_tuple(json::Json(R"({"a": []})"), "$a", "[]"),
        std::make_tuple(json::Json(R"({"a": {}})"), "$a", "{}"),

        // Multiple replacements
        std::make_tuple(json::Json(R"({"a": 1, "b":"1", "c":true, "d":false, "e":null, "f":[], "g":{}})"),
                        "$a $b $c $d $e $f $g",
                        "1 1 true false null [] {}"),

        // Non-existent definitions (should remain as literals)
        std::make_tuple(json::Json(R"({"a": 1, "b":"1", "c":true, "d":false, "e":null, "f":[], "g":{}})"),
                        "$a $b $c $d $e $f $g $no-def 123",
                        "1 1 true false null [] {} $no-def 123"),

        // Escaped variables
        std::make_tuple(json::Json(R"({"a": "value"})"), "\\$a", "$a"),
        std::make_tuple(json::Json(R"({"a": "value"})"), "\\$a$a", "$avalue"),

        // Nested definitions
        std::make_tuple(json::Json(R"({"a": "value", "b": "$a", "c": "$b"})"), "$c", "value"),
        std::make_tuple(json::Json(R"({"a": "$b", "b": "value"})"), "$a", "value"),

        // Complex nested cases
        std::make_tuple(json::Json(R"({"host": "localhost", "port": "8080", "url": "http://$host:$port"})"),
                        "$url",
                        "http://localhost:8080"),
        std::make_tuple(json::Json(R"({"base": "/api", "version": "v1", "endpoint": "$base/$version"})"),
                        "GET $endpoint/users",
                        "GET /api/v1/users"),

        // Multiple same variable in one string
        std::make_tuple(json::Json(R"({"user": "admin"})"), "$user loves $user", "admin loves admin"),

        // Variables with underscores and numbers
        std::make_tuple(json::Json(R"({"var_123": "test", "VAR_CAPS": "caps"})"),
                        "$var_123 and $VAR_CAPS",
                        "test and caps"),

        // Edge case: $ at end of string
        std::make_tuple(json::Json(R"({"a": "value"})"), "price is $", "price is $"),

        // Edge case: $ followed by non-alphanumeric
        std::make_tuple(json::Json(R"({"a": "value"})"), "cost $19.99", "cost $19.99"),

        // Edge case: Variable name boundaries
        std::make_tuple(json::Json(R"({"ab": "found", "abc": "notfound"})"), "$ab-$abc", "found-notfound"),

        // Complex string with mixed content
        std::make_tuple(json::Json(R"({"protocol": "https", "host": "api.example.com", "path": "/v1/users"})"),
                        "curl -X GET '$protocol://$host$path' -H 'Accept: application/json'",
                        "curl -X GET 'https://api.example.com/v1/users' -H 'Accept: application/json'"),

        // Multiple escapes
        std::make_tuple(json::Json(R"({"price": "10"})"), "\\$price costs \\$price", "$price costs $price"),

        // Mixed escaped and unescaped
        std::make_tuple(json::Json(R"({"amount": "50"})"), "\\$amount = $amount USD", "$amount = 50 USD"),

        // Empty string handling
        std::make_tuple(json::Json(R"({"empty": ""})"), "value: '$empty'", "value: ''"),

        // No variables in string
        std::make_tuple(json::Json(R"({"a": "value"})"), "no variables here", "no variables here"),

        // Only $ character
        std::make_tuple(json::Json(R"({"a": "value"})"), "$", "$"),

        // Definitions with special characters in values
        std::make_tuple(json::Json(R"({"special": "hello@world.com"})"), "Email: $special", "Email: hello@world.com"),
        std::make_tuple(json::Json(R"({"path": "/home/user/docs"})"), "Path: $path", "Path: /home/user/docs"),

        // Chain of definitions with different patterns
        std::make_tuple(json::Json(R"({"a": "1", "b": "prefix $a", "c": "$b suffix", "d": "start $c end"})"),
                        "$d",
                        "start prefix 1 suffix end")));

// Test complex dependency resolution scenarios
TEST(DefsComplexDependencyTest, ComplexDependencies)
{
    // Test deep nesting (4 levels)
    {
        auto definitions = json::Json(R"({
            "level1": "base",
            "level2": "$level1 l2", 
            "level3": "$level2 l3",
            "level4": "$level3 l4"
        })");
        auto def = defs::Definitions(definitions);
        ASSERT_EQ(def.replace("$level4"), "base l2 l3 l4");
    }

    // Test multiple dependencies in one definition
    {
        auto definitions = json::Json(R"({
            "first": "Hello",
            "second": "World", 
            "third": "!",
            "greeting": "$first $second$third"
        })");
        auto def = defs::Definitions(definitions);
        ASSERT_EQ(def.replace("$greeting"), "Hello World!");
    }

    // Test mixed resolved and unresolved in same string
    {
        auto definitions = json::Json(R"({
            "existing": "found"
        })");
        auto def = defs::Definitions(definitions);
        ASSERT_EQ(def.replace("$existing and $missing and $existing"), "found and $missing and found");
    }
}

// Test edge cases for variable name parsing
TEST(DefsVariableNameParsingTest, VariableNameParsing)
{
    auto definitions = json::Json(R"({
        "a": "short",
        "longer_name": "longer", 
        "name123": "numeric",
        "CAPS": "uppercase",
        "MixedCase": "mixed"
    })");
    auto def = defs::Definitions(definitions);

    // Test that variable names are parsed correctly with boundaries
    ASSERT_EQ(def.replace("$a extra"), "short extra");
    ASSERT_EQ(def.replace("prefix_$longer_name suffix"), "prefix_longer suffix");
    ASSERT_EQ(def.replace("$name123 extra"), "numeric extra");
    ASSERT_EQ(def.replace("$CAPS-test"), "uppercase-test");
    ASSERT_EQ(def.replace("$MixedCase.property"), "mixed.property");
}

// Test error messages contain useful information
TEST(DefsErrorMessagesTest, ErrorMessages)
{
    // Test constructor error message for non-object
    try
    {
        auto def = defs::Definitions(json::Json(R"([])"));
        FAIL() << "Should have thrown exception";
    }
    catch (const std::runtime_error& e)
    {
        std::string message = e.what();
        ASSERT_TRUE(message.find("Definitions must be an object") != std::string::npos);
        ASSERT_TRUE(message.find("array") != std::string::npos);
    }

    // Test constructor error message for $ prefix
    try
    {
        auto def = defs::Definitions(json::Json(R"({"$invalid": "test"})"));
        FAIL() << "Should have thrown exception";
    }
    catch (const std::runtime_error& e)
    {
        std::string message = e.what();
        ASSERT_TRUE(message.find("cannot start with '$'") != std::string::npos);
        ASSERT_TRUE(message.find("$invalid") != std::string::npos);
    }

    // Test get error message
    auto def = defs::Definitions(json::Json(R"({"existing": "value"})"));
    try
    {
        def.get("/missing");
        FAIL() << "Should have thrown exception";
    }
    catch (const std::runtime_error& e)
    {
        std::string message = e.what();
        ASSERT_TRUE(message.find("Definition") != std::string::npos);
        ASSERT_TRUE(message.find("not found") != std::string::npos);
        ASSERT_TRUE(message.find("missing") != std::string::npos);
    }

    // Test circular reference error message
    try
    {
        auto def = defs::Definitions(json::Json(R"({"a": "$b", "b": "$a"})"));
        FAIL() << "Should have thrown exception";
    }
    catch (const std::runtime_error& e)
    {
        std::string message = e.what();
        ASSERT_TRUE(message.find("Circular reference detected") != std::string::npos);
    }
}

// Test performance with large number of definitions
TEST(DefsPerformanceTest, LargeDefinitions)
{
    // Create a JSON with many definitions
    std::string jsonStr = "{";
    for (int i = 0; i < 1000; ++i)
    {
        if (i > 0)
            jsonStr += ",";
        jsonStr += "\"var" + std::to_string(i) + "\":\"value" + std::to_string(i) + "\"";
    }
    jsonStr += "}";

    // Use .c_str() to convert std::string to const char*
    auto definitions = json::Json(jsonStr.c_str());

    // Should construct without issues
    ASSERT_NO_THROW(auto def = defs::Definitions(definitions));

    auto def = defs::Definitions(definitions);

    // Should handle replacement efficiently
    ASSERT_EQ(def.replace("$var0"), "value0");
    ASSERT_EQ(def.replace("$var999"), "value999");
    ASSERT_EQ(def.replace("$var500 and $var600"), "value500 and value600");
}

// Test special JSON values in definitions
TEST(DefsSpecialJsonValuesTest, SpecialValues)
{
    auto definitions = json::Json(R"({
        "zero": 0,
        "negative": -42,
        "decimal": 3.14,
        "scientific": 1.23e-4,
        "empty_string": "",
        "space_string": " ",
        "unicode": "héllo wörld 🌍",
        "quotes": "She said \"hello\"",
        "backslash": "path\\to\\file",
        "newline": "line1\nline2",
        "tab": "col1\tcol2"
    })");

    auto def = defs::Definitions(definitions);

    ASSERT_EQ(def.replace("$zero"), "0");
    ASSERT_EQ(def.replace("$negative"), "-42");
    ASSERT_EQ(def.replace("$decimal"), "3.14");
    ASSERT_EQ(def.replace("$scientific"), "0.000123");
    ASSERT_EQ(def.replace("'$empty_string'"), "''");
    ASSERT_EQ(def.replace("'$space_string'"), "' '");
    ASSERT_EQ(def.replace("$unicode"), "héllo wörld 🌍");
}

// Test DefinitionsBuilder
TEST(DefsBuilderTest, Builder)
{
    auto builder = defs::DefinitionsBuilder();

    // Test successful build
    auto definitions = json::Json(R"({"test": "value"})");
    auto def = builder.build(definitions);
    ASSERT_NE(def, nullptr);

    auto result = def->replace("$test");
    ASSERT_EQ(result, "value");

    // Test that builder handles errors properly
    auto invalidDefinitions = json::Json(R"([])");
    ASSERT_THROW(builder.build(invalidDefinitions), std::runtime_error);
}
