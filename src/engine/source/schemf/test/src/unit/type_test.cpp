#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/json.hpp>
#include <schemf/type.hpp>

using namespace schemf;

// ---------------------------------------------------------------------------
// typeToStr — spot-check all types including the "uncommon" ones
// ---------------------------------------------------------------------------

TEST(TypeTest, TypeToStr_CommonTypes)
{
    EXPECT_STREQ(typeToStr(Type::BOOLEAN), "boolean");
    EXPECT_STREQ(typeToStr(Type::INTEGER), "integer");
    EXPECT_STREQ(typeToStr(Type::LONG), "long");
    EXPECT_STREQ(typeToStr(Type::KEYWORD), "keyword");
    EXPECT_STREQ(typeToStr(Type::TEXT), "text");
    EXPECT_STREQ(typeToStr(Type::DATE), "date");
    EXPECT_STREQ(typeToStr(Type::IP), "ip");
    EXPECT_STREQ(typeToStr(Type::OBJECT), "object");
}

TEST(TypeTest, TypeToStr_NumericVariants)
{
    EXPECT_STREQ(typeToStr(Type::BYTE), "byte");
    EXPECT_STREQ(typeToStr(Type::SHORT), "short");
    EXPECT_STREQ(typeToStr(Type::FLOAT), "float");
    EXPECT_STREQ(typeToStr(Type::HALF_FLOAT), "half_float");
    EXPECT_STREQ(typeToStr(Type::SCALED_FLOAT), "scaled_float");
    EXPECT_STREQ(typeToStr(Type::DOUBLE), "double");
    EXPECT_STREQ(typeToStr(Type::UNSIGNED_LONG), "unsigned_long");
    EXPECT_STREQ(typeToStr(Type::TOKEN_COUNT), "token_count");
}

TEST(TypeTest, TypeToStr_StringVariants)
{
    EXPECT_STREQ(typeToStr(Type::MATCH_ONLY_TEXT), "match_only_text");
    EXPECT_STREQ(typeToStr(Type::WILDCARD), "wildcard");
    EXPECT_STREQ(typeToStr(Type::CONSTANT_KEYWORD), "constant_keyword");
    EXPECT_STREQ(typeToStr(Type::DATE_NANOS), "date_nanos");
    EXPECT_STREQ(typeToStr(Type::BINARY), "binary");
    EXPECT_STREQ(typeToStr(Type::COMPLETION), "completion");
    EXPECT_STREQ(typeToStr(Type::SEARCH_AS_YOU_TYPE), "search_as_you_type");
    EXPECT_STREQ(typeToStr(Type::SEMANTIC), "semantic");
}

TEST(TypeTest, TypeToStr_StructuralTypes)
{
    EXPECT_STREQ(typeToStr(Type::NESTED), "nested");
    EXPECT_STREQ(typeToStr(Type::FLAT_OBJECT), "flat_object");
    EXPECT_STREQ(typeToStr(Type::GEO_POINT), "geo_point");
    EXPECT_STREQ(typeToStr(Type::JOIN), "join");
}

TEST(TypeTest, TypeToStr_IncompatibleTypes)
{
    EXPECT_STREQ(typeToStr(Type::KNN_VECTOR), "knn_vector");
    EXPECT_STREQ(typeToStr(Type::SPARSE_VECTOR), "sparse_vector");
    EXPECT_STREQ(typeToStr(Type::RANK_FEATURE), "rank_feature");
    EXPECT_STREQ(typeToStr(Type::RANK_FEATURES), "rank_features");
    EXPECT_STREQ(typeToStr(Type::PERCOLATOR), "percolator");
    EXPECT_STREQ(typeToStr(Type::STAR_TREE), "star_tree");
    EXPECT_STREQ(typeToStr(Type::DERIVED), "derived");
}

TEST(TypeTest, TypeToStr_RangeTypes)
{
    EXPECT_STREQ(typeToStr(Type::INTEGER_RANGE), "integer_range");
    EXPECT_STREQ(typeToStr(Type::LONG_RANGE), "long_range");
    EXPECT_STREQ(typeToStr(Type::FLOAT_RANGE), "float_range");
    EXPECT_STREQ(typeToStr(Type::DOUBLE_RANGE), "double_range");
    EXPECT_STREQ(typeToStr(Type::DATE_RANGE), "date_range");
    EXPECT_STREQ(typeToStr(Type::IP_RANGE), "ip_range");
}

TEST(TypeTest, TypeToStr_ErrorReturnsErrorString)
{
    EXPECT_STREQ(typeToStr(Type::ERROR), "error");
}

// ---------------------------------------------------------------------------
// strToType — round-trips with typeToStr, plus unknown input
// ---------------------------------------------------------------------------

TEST(TypeTest, StrToType_RoundTripAllTypes)
{
    const std::vector<Type> allTypes = {
        Type::BOOLEAN,
        Type::BYTE,
        Type::SHORT,
        Type::INTEGER,
        Type::LONG,
        Type::FLOAT,
        Type::HALF_FLOAT,
        Type::SCALED_FLOAT,
        Type::DOUBLE,
        Type::KEYWORD,
        Type::TEXT,
        Type::MATCH_ONLY_TEXT,
        Type::WILDCARD,
        Type::CONSTANT_KEYWORD,
        Type::DATE,
        Type::DATE_NANOS,
        Type::IP,
        Type::BINARY,
        Type::OBJECT,
        Type::NESTED,
        Type::FLAT_OBJECT,
        Type::GEO_POINT,
        Type::UNSIGNED_LONG,
        Type::COMPLETION,
        Type::SEARCH_AS_YOU_TYPE,
        Type::TOKEN_COUNT,
        Type::SEMANTIC,
        Type::JOIN,
        Type::KNN_VECTOR,
        Type::SPARSE_VECTOR,
        Type::RANK_FEATURE,
        Type::RANK_FEATURES,
        Type::PERCOLATOR,
        Type::STAR_TREE,
        Type::DERIVED,
        Type::INTEGER_RANGE,
        Type::LONG_RANGE,
        Type::FLOAT_RANGE,
        Type::DOUBLE_RANGE,
        Type::DATE_RANGE,
        Type::IP_RANGE,
    };

    for (auto t : allTypes)
    {
        EXPECT_EQ(strToType(typeToStr(t)), t) << "Round-trip failed for type: " << typeToStr(t);
    }
}

TEST(TypeTest, StrToType_UnknownStringReturnsError)
{
    EXPECT_EQ(strToType("unknown_type"), Type::ERROR);
    EXPECT_EQ(strToType(""), Type::ERROR);
    EXPECT_EQ(strToType("INTEGER"), Type::ERROR); // case-sensitive
}

// ---------------------------------------------------------------------------
// typeToJType
// ---------------------------------------------------------------------------

TEST(TypeTest, TypeToJType_BooleanMapsToBoolean)
{
    EXPECT_EQ(typeToJType(Type::BOOLEAN), json::Json::Type::Boolean);
}

TEST(TypeTest, TypeToJType_NumericTypesMapToNumber)
{
    EXPECT_EQ(typeToJType(Type::BYTE), json::Json::Type::Number);
    EXPECT_EQ(typeToJType(Type::SHORT), json::Json::Type::Number);
    EXPECT_EQ(typeToJType(Type::INTEGER), json::Json::Type::Number);
    EXPECT_EQ(typeToJType(Type::LONG), json::Json::Type::Number);
    EXPECT_EQ(typeToJType(Type::FLOAT), json::Json::Type::Number);
    EXPECT_EQ(typeToJType(Type::HALF_FLOAT), json::Json::Type::Number);
    EXPECT_EQ(typeToJType(Type::SCALED_FLOAT), json::Json::Type::Number);
    EXPECT_EQ(typeToJType(Type::DOUBLE), json::Json::Type::Number);
    EXPECT_EQ(typeToJType(Type::UNSIGNED_LONG), json::Json::Type::Number);
    EXPECT_EQ(typeToJType(Type::TOKEN_COUNT), json::Json::Type::Number);
}

TEST(TypeTest, TypeToJType_StringTypesMapToString)
{
    EXPECT_EQ(typeToJType(Type::KEYWORD), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::TEXT), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::MATCH_ONLY_TEXT), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::WILDCARD), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::CONSTANT_KEYWORD), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::DATE), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::DATE_NANOS), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::IP), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::BINARY), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::COMPLETION), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::SEARCH_AS_YOU_TYPE), json::Json::Type::String);
    EXPECT_EQ(typeToJType(Type::SEMANTIC), json::Json::Type::String);
}

TEST(TypeTest, TypeToJType_ObjectTypesMapToObject)
{
    EXPECT_EQ(typeToJType(Type::OBJECT), json::Json::Type::Object);
    EXPECT_EQ(typeToJType(Type::NESTED), json::Json::Type::Object);
    EXPECT_EQ(typeToJType(Type::FLAT_OBJECT), json::Json::Type::Object);
    EXPECT_EQ(typeToJType(Type::GEO_POINT), json::Json::Type::Object);
    EXPECT_EQ(typeToJType(Type::JOIN), json::Json::Type::Object);
}

TEST(TypeTest, TypeToJType_IncompatibleTypesMapToNull)
{
    EXPECT_EQ(typeToJType(Type::KNN_VECTOR), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::SPARSE_VECTOR), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::RANK_FEATURE), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::RANK_FEATURES), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::PERCOLATOR), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::STAR_TREE), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::DERIVED), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::INTEGER_RANGE), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::LONG_RANGE), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::FLOAT_RANGE), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::DOUBLE_RANGE), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::DATE_RANGE), json::Json::Type::Null);
    EXPECT_EQ(typeToJType(Type::IP_RANGE), json::Json::Type::Null);
}

// ---------------------------------------------------------------------------
// hasProperties
// ---------------------------------------------------------------------------

TEST(TypeTest, HasProperties_ObjectTypesReturnTrue)
{
    EXPECT_TRUE(hasProperties(Type::OBJECT));
    EXPECT_TRUE(hasProperties(Type::NESTED));
    EXPECT_TRUE(hasProperties(Type::FLAT_OBJECT));
}

TEST(TypeTest, HasProperties_NonObjectTypesReturnFalse)
{
    EXPECT_FALSE(hasProperties(Type::KEYWORD));
    EXPECT_FALSE(hasProperties(Type::INTEGER));
    EXPECT_FALSE(hasProperties(Type::BOOLEAN));
    EXPECT_FALSE(hasProperties(Type::IP));
    EXPECT_FALSE(hasProperties(Type::GEO_POINT));
    EXPECT_FALSE(hasProperties(Type::KNN_VECTOR));
    EXPECT_FALSE(hasProperties(Type::ERROR));
}
