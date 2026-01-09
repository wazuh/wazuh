#ifndef _SCHEMF_TYPE_HPP
#define _SCHEMF_TYPE_HPP

#include <string>

namespace schemf
{
/**
 * @brief Schema types.
 *
 */
enum class Type
{
    ERROR = -1,
    BOOLEAN = 0,
    BYTE,
    SHORT,
    INTEGER,
    LONG,
    FLOAT,
    HALF_FLOAT,
    SCALED_FLOAT,
    DOUBLE,
    KEYWORD,
    TEXT,
    MATCH_ONLY_TEXT,
    WILDCARD,
    CONSTANT_KEYWORD,
    DATE,
    DATE_NANOS,
    IP,
    BINARY,
    OBJECT,
    NESTED,
    FLAT_OBJECT,
    GEO_POINT,
    UNSIGNED_LONG,
    COMPLETION,
    SEARCH_AS_YOU_TYPE,
    TOKEN_COUNT,
    SEMANTIC,
    JOIN,
    KNN_VECTOR,
    SPARSE_VECTOR,
    RANK_FEATURE,
    RANK_FEATURES,
    PERCOLATOR,
    STAR_TREE,
    DERIVED,
    INTEGER_RANGE,
    LONG_RANGE,
    FLOAT_RANGE,
    DOUBLE_RANGE,
    DATE_RANGE,
    IP_RANGE,

};

inline constexpr bool hasProperties(Type type)
{
    switch (type)
    {
        case Type::OBJECT:
        case Type::NESTED:
        case Type::FLAT_OBJECT: return true;
        default: return false;
    }
}

inline constexpr auto typeToStr(Type type)
{
    switch (type)
    {
        case Type::BOOLEAN: return "boolean";
        case Type::BYTE: return "byte";
        case Type::SHORT: return "short";
        case Type::INTEGER: return "integer";
        case Type::LONG: return "long";
        case Type::FLOAT: return "float";
        case Type::HALF_FLOAT: return "half_float";
        case Type::SCALED_FLOAT: return "scaled_float";
        case Type::DOUBLE: return "double";
        case Type::KEYWORD: return "keyword";
        case Type::TEXT: return "text";
        case Type::MATCH_ONLY_TEXT: return "match_only_text";
        case Type::WILDCARD: return "wildcard";
        case Type::CONSTANT_KEYWORD: return "constant_keyword";
        case Type::DATE: return "date";
        case Type::DATE_NANOS: return "date_nanos";
        case Type::IP: return "ip";
        case Type::BINARY: return "binary";
        case Type::OBJECT: return "object";
        case Type::NESTED: return "nested";
        case Type::FLAT_OBJECT: return "flat_object";
        case Type::GEO_POINT: return "geo_point";
        case Type::UNSIGNED_LONG: return "unsigned_long";
        case Type::COMPLETION: return "completion";
        case Type::SEARCH_AS_YOU_TYPE: return "search_as_you_type";
        case Type::TOKEN_COUNT: return "token_count";
        case Type::SEMANTIC: return "semantic";
        case Type::JOIN: return "join";
        case Type::KNN_VECTOR: return "knn_vector";
        case Type::SPARSE_VECTOR: return "sparse_vector";
        case Type::RANK_FEATURES: return "rank_features";
        case Type::RANK_FEATURE: return "rank_feature";
        case Type::PERCOLATOR: return "percolator";
        case Type::STAR_TREE: return "star_tree";
        case Type::DERIVED: return "derived";
        case Type::INTEGER_RANGE: return "integer_range";
        case Type::LONG_RANGE: return "long_range";
        case Type::FLOAT_RANGE: return "float_range";
        case Type::DOUBLE_RANGE: return "double_range";
        case Type::DATE_RANGE: return "date_range";
        case Type::IP_RANGE: return "ip_range";
        default: return "error";
    }
}

inline constexpr auto strToType(std::string_view strType)
{
    if (typeToStr(Type::BOOLEAN) == strType)
        return Type::BOOLEAN;
    if (typeToStr(Type::BYTE) == strType)
        return Type::BYTE;
    if (typeToStr(Type::SHORT) == strType)
        return Type::SHORT;
    if (typeToStr(Type::INTEGER) == strType)
        return Type::INTEGER;
    if (typeToStr(Type::LONG) == strType)
        return Type::LONG;
    if (typeToStr(Type::FLOAT) == strType)
        return Type::FLOAT;
    if (typeToStr(Type::HALF_FLOAT) == strType)
        return Type::HALF_FLOAT;
    if (typeToStr(Type::SCALED_FLOAT) == strType)
        return Type::SCALED_FLOAT;
    if (typeToStr(Type::DOUBLE) == strType)
        return Type::DOUBLE;
    if (typeToStr(Type::KEYWORD) == strType)
        return Type::KEYWORD;
    if (typeToStr(Type::TEXT) == strType)
        return Type::TEXT;
    if (typeToStr(Type::MATCH_ONLY_TEXT) == strType)
        return Type::MATCH_ONLY_TEXT;
    if (typeToStr(Type::WILDCARD) == strType)
        return Type::WILDCARD;
    if (typeToStr(Type::CONSTANT_KEYWORD) == strType)
        return Type::CONSTANT_KEYWORD;
    if (typeToStr(Type::DATE) == strType)
        return Type::DATE;
    if (typeToStr(Type::DATE_NANOS) == strType)
        return Type::DATE_NANOS;
    if (typeToStr(Type::IP) == strType)
        return Type::IP;
    if (typeToStr(Type::BINARY) == strType)
        return Type::BINARY;
    if (typeToStr(Type::OBJECT) == strType)
        return Type::OBJECT;
    if (typeToStr(Type::NESTED) == strType)
        return Type::NESTED;
    if (typeToStr(Type::FLAT_OBJECT) == strType)
        return Type::FLAT_OBJECT;
    if (typeToStr(Type::GEO_POINT) == strType)
        return Type::GEO_POINT;
    if (typeToStr(Type::UNSIGNED_LONG) == strType)
        return Type::UNSIGNED_LONG;
    if (typeToStr(Type::COMPLETION) == strType)
        return Type::COMPLETION;
    if (typeToStr(Type::SEARCH_AS_YOU_TYPE) == strType)
        return Type::SEARCH_AS_YOU_TYPE;
    if (typeToStr(Type::TOKEN_COUNT) == strType)
        return Type::TOKEN_COUNT;
    if (typeToStr(Type::SEMANTIC) == strType)
        return Type::SEMANTIC;
    if (typeToStr(Type::JOIN) == strType)
        return Type::JOIN;
    if (typeToStr(Type::KNN_VECTOR) == strType)
        return Type::KNN_VECTOR;
    if (typeToStr(Type::SPARSE_VECTOR) == strType)
        return Type::SPARSE_VECTOR;
    if (typeToStr(Type::RANK_FEATURES) == strType)
        return Type::RANK_FEATURES;
    if (typeToStr(Type::RANK_FEATURE) == strType)
        return Type::RANK_FEATURE;
    if (typeToStr(Type::PERCOLATOR) == strType)
        return Type::PERCOLATOR;
    if (typeToStr(Type::STAR_TREE) == strType)
        return Type::STAR_TREE;
    if (typeToStr(Type::DERIVED) == strType)
        return Type::DERIVED;
    if (typeToStr(Type::INTEGER_RANGE) == strType)
        return Type::INTEGER_RANGE;
    if (typeToStr(Type::LONG_RANGE) == strType)
        return Type::LONG_RANGE;
    if (typeToStr(Type::FLOAT_RANGE) == strType)
        return Type::FLOAT_RANGE;
    if (typeToStr(Type::DOUBLE_RANGE) == strType)
        return Type::DOUBLE_RANGE;
    if (typeToStr(Type::DATE_RANGE) == strType)
        return Type::DATE_RANGE;
    if (typeToStr(Type::IP_RANGE) == strType)
        return Type::IP_RANGE;
    return Type::ERROR;
}

inline constexpr auto typeToJType(Type type)
{
    switch (type)
    {
        case Type::BOOLEAN: return json::Json::Type::Boolean;
        case Type::BYTE: return json::Json::Type::Number;
        case Type::SHORT: return json::Json::Type::Number;
        case Type::INTEGER: return json::Json::Type::Number;
        case Type::LONG: return json::Json::Type::Number;
        case Type::FLOAT: return json::Json::Type::Number;
        case Type::HALF_FLOAT: return json::Json::Type::Number;
        case Type::SCALED_FLOAT: return json::Json::Type::Number;
        case Type::DOUBLE: return json::Json::Type::Number;
        case Type::UNSIGNED_LONG: return json::Json::Type::Number;
        case Type::KEYWORD: return json::Json::Type::String;
        case Type::TEXT: return json::Json::Type::String;
        case Type::MATCH_ONLY_TEXT: return json::Json::Type::String;
        case Type::WILDCARD: return json::Json::Type::String;
        case Type::CONSTANT_KEYWORD: return json::Json::Type::String;
        case Type::DATE: return json::Json::Type::String;
        case Type::DATE_NANOS: return json::Json::Type::String;
        case Type::IP: return json::Json::Type::String;
        case Type::BINARY: return json::Json::Type::String;
        case Type::OBJECT: return json::Json::Type::Object;
        case Type::NESTED: return json::Json::Type::Object;
        case Type::FLAT_OBJECT: return json::Json::Type::Object;
        case Type::GEO_POINT: return json::Json::Type::Object;
        case Type::COMPLETION: return json::Json::Type::String;
        case Type::SEARCH_AS_YOU_TYPE: return json::Json::Type::String;
        case Type::TOKEN_COUNT: return json::Json::Type::Number;
        case Type::SEMANTIC: return json::Json::Type::String;
        case Type::JOIN: return json::Json::Type::Object;
        default: return json::Json::Type::Null;
    }
}

} // namespace schemf

#endif // _SCHEMF_TYPE_HPP
