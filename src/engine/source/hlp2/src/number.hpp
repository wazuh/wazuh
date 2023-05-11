#ifndef _HLP_NUMBER_HPP
#define _HLP_NUMBER_HPP

#include <charconv>
#include <cmath>
#include <functional>
#include <iostream>
#include <stdexcept>
#include <string>
#include <vector>

#include <fast_float/fast_float.h>

#include <fmt/format.h>
#include <json/json.hpp>

#include <hlp/base.hpp>
#include <hlp/parsec.hpp>

namespace utils
{
std::function<void(json::Json&)> setNumberHandler(const std::string& path, int8_t val);
std::function<void(json::Json&)> setNumberHandler(const std::string& path, int64_t val);
std::function<void(json::Json&)> setNumberHandler(const std::string& path, float_t val);
std::function<void(json::Json&)> setNumberHandler(const std::string& path, double_t val);
std::from_chars_result from_chars(const char* first, const char* last, int8_t& val);
std::from_chars_result from_chars(const char* first, const char* last, int64_t& val);
std::from_chars_result from_chars(const char* first, const char* last, float& val);
std::from_chars_result from_chars(const char* first, const char* last, double& val);

// Offset the number of bytes in the data buffer
template<typename T>
typename std::enable_if<std::is_same<T, int32_t>::value || std::is_same<T, int64_t>::value
                            || std::is_same<T, int8_t>::value,
                        std::size_t>::type
offsetNum(const std::string_view& data)
{
    bool sign = data[0] == '-' || data[0] == '+';                     // Check if the number is signed
    auto numLen = data.find_first_not_of("0123456789", sign ? 1 : 0); // Find the first non-numeric character
    if (numLen == std::string_view::npos)
    {
        numLen = data.length();
    }
    else if (sign)
    {
        if (numLen == 1)
        {
            numLen = 0; // No digits found, only the sign
        }
        else
        {
            numLen++;
        }
    }
    return numLen;
}

// Offset the number of bytes in the data buffer
template<typename T>
typename std::enable_if<std::is_same<T, double>::value || std::is_same<T, float>::value, std::size_t>::type
offsetNum(const std::string_view& data)
{
    // IEEE 754
    auto offset = data.find_first_not_of("0123456789.eE+-", 0); // Find the first non-numeric character
    if (offset == std::string_view::npos)
    {
        offset = data.length();
    }
    return offset;
}

} // namespace utils

namespace hlp
{
template<class T>
parsec::MergeableParser<jFnList> getNumericParser(const hlp::ParserSpec& spec)
{
    if (!spec.args().empty())
    {
        throw std::runtime_error("numeric parser doesn't accept parameters");
    }

    /******************************************************
      Stege 4: Define the semantic action
     ******************************************************/
    auto semanticProcessor = [spec](jFnList& result,
                                    const std::deque<std::string_view>& tokens,
                                    const parsec::ParserState& state) -> std::pair<bool, std::optional<parsec::TraceP>>
    {
        // tokens.size() == 1 because the parser is a single token parser
        auto numToken = std::string(tokens.front());
        T val;

        // Check if the number is valid
        auto [ptr, ec] {utils::from_chars(numToken.data(), numToken.data() + numToken.size(), val)};
        if (ec == std::errc())
        {
            result.push_back(utils::setNumberHandler(spec.targetField(), val));
            if (state.isTraceEnabled())
            {
                auto trace = fmt::format("[success] {} -> {} -> {}", spec.name(), numToken, val);
                auto offset = tokens.front().data() + tokens.front().size() - state.getData().data();

                return {true, parsec::TraceP(trace, offset)};
            }
            return {true, std::nullopt};
        }

        if (state.isTraceEnabled())
        {
            auto trace = fmt::format("[failed] {} -> Invalid number: '{}'.", spec.name(), numToken);
            if (ec == std::errc::invalid_argument)
            {
                trace += " The string is not a valid number.";

            }
            else if (ec == std::errc::result_out_of_range)
            {
                trace += " The string is a valid number but out of range.";
            }
            auto offset = numToken.data() - state.getData().data();
            return {false, parsec::TraceP(trace, offset)};
        }

        return {false, std::nullopt};
    };

    return [semanticProcessor, spec](const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
    {
        /******************************************************
         Stege 1: Preprocess: Check EOF and endtoken
        ******************************************************/
        auto result = parsec::MergeableResultP<jFnList>::failure(state);
        if (state.getRemainingSize() == 0)
        {
            if (state.isTraceEnabled())
            {
                auto msg = fmt::format("[failure] {} -> EOF reached", spec.name());
                result.concatenateTraces(msg);
            }
            return result;
        }


        /******************************************************
         Stege 2: Sintactic action
        ******************************************************/
        auto numCandidate = state.getRemainingData();
        auto until = utils::offsetNum<T>(numCandidate);

        // Check length of the number
        if (until == 0)
        {
            if (state.isTraceEnabled())
            {
                auto msg = fmt::format("[failure] {} -> Invalid number: '{}'.", spec.name(), numCandidate);
                result.concatenateTraces(msg);
            }
            return result;
        }
        // extract the number
        numCandidate = numCandidate.substr(0, until);

        /******************************************************
         Stege 3: Prepare the result with the semantic action
        ******************************************************/
        parsec::Mergeable<jFnList> mergeable {.m_semanticProcessor = semanticProcessor, .m_tokens = {numCandidate}};
        result.setSuccess(state.advance(numCandidate.size()), std::move(mergeable));

        return result;
    };
}

} // namespace hlp
#endif // _HLP_NUMBER_HPP
