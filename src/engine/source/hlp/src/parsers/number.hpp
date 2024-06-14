#ifndef _HLP_NUMBER_HPP
#define _HLP_NUMBER_HPP

#include <charconv>
#include <cmath>
#include <fast_float/fast_float.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <string_view>

#include <fmt/format.h>

#include "hlp.hpp"
#include "syntax.hpp"

namespace utils
{
void setNumber(std::string_view targetField, json::Json& doc, int8_t val);
void setNumber(std::string_view targetField, json::Json& doc, int64_t val);
void setNumber(std::string_view targetField, json::Json& doc, float_t val);
void setNumber(std::string_view targetField, json::Json& doc, double_t val);
std::from_chars_result from_chars(const char* first, const char* last, int8_t& val);
std::from_chars_result from_chars(const char* first, const char* last, int64_t& val);
std::from_chars_result from_chars(const char* first, const char* last, float& val);
std::from_chars_result from_chars(const char* first, const char* last, double& val);
} // namespace utils

namespace
{
using namespace hlp;
using namespace hlp::parser;

template<typename T>
Mapper getMapper(const std::string& targetField, T val)
{
    return [targetField, val](json::Json& event)
    {
        utils::setNumber(targetField, event, val);
    };
}

template<typename T>
SemParser getSemParser(const std::string& targetField)
{
    return [targetField](std::string_view parsed) -> std::variant<Mapper, base::Error>
    {
        T val {};
        const auto [ptr, ec] {utils::from_chars(parsed.begin(), parsed.end(), val)};
        if (ec == std::errc())
        {
            if (!targetField.empty())
            {
                return getMapper<T>(targetField, val);
            }

            return noMapper();
        }
        else if (ec == std::errc::result_out_of_range)
        {
            return base::Error {"Number is out of range"};
        }

        return base::Error {"Expected a number"};
    };
}

template<class T>
syntax::Parser getSynParser()
{
    using namespace syntax::combinators;
    using namespace syntax::parsers;

    if constexpr (std::is_integral_v<T>)
    {
        // For int types exclude the possibility of scientific notation
        const auto synP = opt(char_('-')) & many1(digit()) & opt(char_('.')) & many(digit());
        return synP;
    }
    else
    {
        const auto synP = opt(char_('-')) & many1(digit()) & opt(char_('.')) & many(digit())
                          & opt((char_('e') | char_('E')) & opt(char_('+') | char_('-')) & many1(digit()));
        return synP;
    }
}
} // namespace

namespace hlp::parsers
{

template<class T>
Parser getNumericParser(const Params& params)
{
    if (!params.options.empty())
    {
        throw std::runtime_error("numeric parser doesn't accept parameters");
    }

    const auto synP = getSynParser<T>();
    const auto targetPath = params.targetField.empty() ? "" : params.targetField;
    const auto semP = getSemParser<T>(targetPath);

    return [name = params.name, synP, semP](std::string_view text)
    {
        auto synR = synP(text);
        if (synR.failure())
        {
            return abs::makeFailure<ResultT>(synR.remaining(), name);
        }
        else
        {
            return abs::makeSuccess(SemToken {syntax::parsed(synR, text), semP}, synR.remaining());
        }
    };
}

} // namespace hlp::parsers
#endif // _HLP_NUMBER_HPP
