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
    DATE,
    DATE_NANOS,
    IP,
    BINARY,
    OBJECT,
    NESTED,
    GEO_POINT
};

inline constexpr bool hasProperties(Type type)
{
    switch (type)
    {
        case Type::OBJECT:
        case Type::NESTED: return true;
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
        case Type::DATE: return "date";
        case Type::DATE_NANOS: return "date_nanos";
        case Type::IP: return "ip";
        case Type::BINARY: return "binary";
        case Type::OBJECT: return "object";
        case Type::NESTED: return "nested";
        case Type::GEO_POINT: return "geo_point";
        default: return "error";
    }
}

inline auto strToType(const std::string& strType)
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
    if (typeToStr(Type::GEO_POINT) == strType)
        return Type::GEO_POINT;
    return Type::ERROR;
}

} // namespace schemf

#endif // _SCHEMF_TYPE_HPP
