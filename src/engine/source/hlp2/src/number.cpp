#include <string>
#include <vector>

#include <fmt/format.h>

#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

#include "number.hpp"

namespace utils
{
std::function<void(json::Json&)> setNumberHandler(const std::string& path, int8_t val)
{
    return [path, val](json::Json& doc) { doc.setInt(val, path); };
}

std::function<void(json::Json&)> setNumberHandler(const std::string& path, int64_t val)
{
    return [path, val](json::Json& doc) { doc.setInt64(val, path); };
}

std::function<void(json::Json&)> setNumberHandler(const std::string& path, float_t val)
{
    return [path, val](json::Json& doc) { doc.setFloat(val, path); };
}

std::function<void(json::Json&)> setNumberHandler(const std::string& path, double_t val)
{
    return [path, val](json::Json& doc) { doc.setDouble(val, path); };
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

parsec::MergeableParser<jFnList> getByteParser(const ParserSpec& spec)
{
    return getNumericParser<int8_t>(spec);
}

parsec::MergeableParser<jFnList> getLongParser(const ParserSpec& spec)
{
    return getNumericParser<int64_t>(spec);
}

parsec::MergeableParser<jFnList> getFloatParser(const ParserSpec& spec)
{
    return getNumericParser<float_t>(spec);
}

parsec::MergeableParser<jFnList> getDoubleParser(const ParserSpec& spec)
{
    return getNumericParser<double_t>(spec);
}

parsec::MergeableParser<jFnList> getScaledFloatParser(const ParserSpec& spec)
{
    return getNumericParser<double_t>(spec);
}

} // namespace hlp
