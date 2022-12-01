#include <string>
#include <vector>

#include <fmt/format.h>

#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

#include "number.hpp"

namespace utils
{
void setNumber(json::Json& doc, int8_t val)
{
    doc.setInt(val);
}

void setNumber(json::Json& doc, int64_t val)
{
    doc.setInt64(val);
}

void setNumber(json::Json& doc, float_t val)
{
    doc.setFloat(val);
}

void setNumber(json::Json& doc, double_t val)
{
    doc.setDouble(val);
}

std::from_chars_result from_chars(const char* first, const char* last, int8_t& val)
{
    return std::from_chars(first, last, val);
}

std::from_chars_result from_chars(const char* first, const char* last, int64_t& val)
{
    return std::from_chars(first, last, val);
}

std::from_chars_result from_chars(const char* first, const char* last, float& val)
{
    fast_float::from_chars_result v = fast_float::from_chars(first, last, val);
    return std::from_chars_result {v.ptr, v.ec};
}

std::from_chars_result from_chars(const char* first, const char* last, double& val)
{
    fast_float::from_chars_result v = fast_float::from_chars(first, last, val);
    return std::from_chars_result {v.ptr, v.ec};
}

} // namespace utils

namespace hlp
{

parsec::Parser<json::Json> getByteParser(Stop endTokens, Options lst)
{
    return getNumericParser<int8_t>(endTokens, lst);
}

parsec::Parser<json::Json> getLongParser(Stop endTokens, Options lst)
{
    return getNumericParser<int64_t>(endTokens, lst);
}

parsec::Parser<json::Json> getFloatParser(Stop endTokens, Options lst)
{
    return getNumericParser<float_t>(endTokens, lst);
}

parsec::Parser<json::Json> getDoubleParser(Stop endTokens, Options lst)
{
    return getNumericParser<double_t>(endTokens, lst);
}

parsec::Parser<json::Json> getScaledFloatParser(Stop endTokens, Options lst)
{
    return getNumericParser<double_t>(endTokens, lst);
}

} // namespace hlp
