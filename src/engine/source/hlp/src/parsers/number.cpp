#include <string>
#include <vector>

#include <fmt/format.h>

#include <base/json.hpp>
#include <hlp/hlp.hpp>

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

void setNumber(std::string_view targetField, json::Json& doc, uint64_t val)
{
    doc.setUint64(val, targetField);
}

void setNumber(std::string_view targetField, json::Json& doc, int32_t val)
{
    doc.setInt(val, targetField);
}

void setNumber(std::string_view targetField, json::Json& doc, int16_t val)
{
    doc.setInt(val, targetField);
}

void setNumber(std::string_view targetField, json::Json& doc, HalfFloat val)
{
    // Store as regular float in JSON
    doc.setFloat(val.value, targetField);
}

std::from_chars_result from_chars(const char* first, const char* last, int8_t& val)
{
    int temp;
    auto result = std::from_chars(first, last, temp);
    if (result.ec == std::errc {} && temp >= INT8_MIN && temp <= INT8_MAX)
    {
        val = static_cast<int8_t>(temp);
    }
    else if (result.ec == std::errc {})
    {
        result.ec = std::errc::result_out_of_range;
    }

    return result;
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

std::from_chars_result from_chars(const char* first, const char* last, uint64_t& val)
{
    return std::from_chars(first, last, val);
}

std::from_chars_result from_chars(const char* first, const char* last, int32_t& val)
{
    return std::from_chars(first, last, val);
}

std::from_chars_result from_chars(const char* first, const char* last, int16_t& val)
{
    return std::from_chars(first, last, val);
}

std::from_chars_result from_chars(const char* first, const char* last, HalfFloat& val)
{
    float temp;
    fast_float::from_chars_result result = fast_float::from_chars(first, last, temp);

    if (result.ec == std::errc {} && temp >= HalfFloat::HALF_FLOAT_MIN && temp <= HalfFloat::HALF_FLOAT_MAX)
    {
        val.value = temp;
    }
    else if (result.ec == std::errc {})
    {
        result.ec = std::errc::result_out_of_range;
    }

    return std::from_chars_result {result.ptr, result.ec};
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

Parser getUnsignedLongParser(const Params& params)
{
    return getNumericParser<uint64_t>(params);
}

Parser getIntegerParser(const Params& params)
{
    return getNumericParser<int32_t>(params);
}

Parser getShortParser(const Params& params)
{
    return getNumericParser<int16_t>(params);
}

Parser getHalfFloatParser(const Params& params)
{
    return getNumericParser<utils::HalfFloat>(params);
}

} // namespace hlp::parsers
