#include <string>
#include <vector>

#include <fmt/format.h>

#include <hlp/hlp.hpp>
#include <base/json.hpp>

#include "number.hpp"

namespace utils
{
void setNumber(std::string_view targetField, json::Json& doc, int8_t val)
{
    doc.setInt(val, targetField);
}

void setNumber(std::string_view targetField, json::Json& doc, int64_t val)
{
    doc.setInt64(val, targetField);
}

void setNumber(std::string_view targetField, json::Json& doc, float_t val)
{
    doc.setFloat(val, targetField);
}

void setNumber(std::string_view targetField, json::Json& doc, double_t val)
{
    doc.setDouble(val, targetField);
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

namespace hlp::parsers
{

Parser getByteParser(const Params& params)
{
    return getNumericParser<int8_t>(params);
}

Parser getLongParser(const Params& params)
{
    return getNumericParser<int64_t>(params);
}

Parser getFloatParser(const Params& params)
{
    return getNumericParser<float_t>(params);
}

Parser getDoubleParser(const Params& params)
{
    return getNumericParser<double_t>(params);
}

Parser getScaledFloatParser(const Params& params)
{
    return getNumericParser<double_t>(params);
}

} // namespace hlp::parsers
