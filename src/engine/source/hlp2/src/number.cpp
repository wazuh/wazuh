#include <hlp/parsec.hpp>
#include <string>
#include <json/json.hpp>
#include <optional>
#include <vector>
#include "number.hpp"
#include "fmt/format.h"

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;

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
    return std::from_chars_result{v.ptr, v.ec};
}

std::from_chars_result from_chars(const char* first, const char* last, double& val)
{
    fast_float::from_chars_result v = fast_float::from_chars(first, last, val);
    return std::from_chars_result{v.ptr, v.ec};
}

} // namespace utils

namespace hlp
{


parsec::Parser<json::Json> getByteParser(Stop str, Options lst)
{
    return getNumericParser<int8_t>(str, lst);
}

parsec::Parser<json::Json> getLongParser(Stop str, Options lst)
{
    return getNumericParser<int64_t>(str, lst);
}

parsec::Parser<json::Json> getFloatParser(Stop str, Options lst)
{
    return getNumericParser<float_t>(str, lst);
}

parsec::Parser<json::Json> getDoubleParser(Stop str, Options lst)
{
    return getNumericParser<double_t>(str, lst);
}

parsec::Parser<json::Json> getScaledFloatParser(Stop str, Options lst)
{
    return getNumericParser<double_t>(str, lst);
}


} // HLP namespace



