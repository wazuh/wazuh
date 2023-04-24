#ifndef _HLP3_HLP3_HPP
#define _HLP3_HLP3_HPP

#include <hlp3/parser.hpp>
#include <tuple>
#include <deque>
#include <json/json.hpp>
#include <arpa/inet.h>


// Parsers builders
namespace hlp3::parser
{
namespace builder
{

} // namespace builder

namespace combinator
{

// cartesian product
template<typename L, typename R>
Parser<std::tuple<L, R>> operator&(const Parser<L>& l, const Parser<R>& r)
{
    return [l, r](InputP input) -> ResultP<std::tuple<L, R>>
    {
        auto resultL = l(input);
        if (!resultL)
        {
            auto result = ResultP<std::tuple<L, R>>::failure();
            return result.concatenateTraces(std::move(resultL));
        }

        auto resultR = r(resultL.getRemaining());
        if (!resultR)
        {
            auto result = ResultP<std::tuple<L, R>>::failure();
            return result.concatenateTraces(std::move(resultL)).concatenateTraces(std::move(resultR));
        }

        return ResultP<std::tuple<L, R>>::success(resultR.getRemaining())
            .concatenateTraces(std::move(resultL))
            .concatenateTraces(std::move(resultR));
    };
}

// Optional parser
template<typename T>
Parser<T> opt(const Parser<T>& p)
{
    return [p](InputP input) -> ResultP<T>
    {
        auto result = p(input);
        if (!result)
        {
            return ResultP<T>::success(input).concatenateTraces(std::move(result));
        }
        return result;
    };
}


template<typename T>
struct preParserResult
{
    T m_result;
    std::list<std::string_view> m_tokens;
    std::function<std::optional<std::string>(T&, const std::list<std::string_view>&)> m_tokenProcessor;

    // Merge the result of T and process the tokens using the tokenProcessor
    std::optional<std::string> mergeResult(T& result) const
    {
        return m_tokenProcessor(result, m_tokens);
    }
};

template<typename T>
Parser<T> seq(const std::list<Parser<preParserResult<T>>>& parsers)
{
    return [parsers](const InputP input) -> ResultP<T>
    {
        InputP currentInput = input;
        std::list<preParserResult<T>> preResults;
        for (auto& parser : parsers)
        {
            auto result = parser(currentInput);
            if (!result)
            {
                return ResultP<T>::failure().concatenateTraces(std::move(result));
            }
            if (auto value = result.popValue(); value)
            {
                preResults.push_back(std::move(*value));
            }
            currentInput = result.getRemaining();
        }

        // if all pre-parsers succeeded, process the tokens
        T finalResult;
        for (auto& preResult : preResults)
        {
            auto error = preResult.mergeResult(finalResult);
            if (error)
            {
                return ResultP<T>::failure(TraceP(*error, currentInput.getPos()));
            }
        }

        return ResultP<T>::success(currentInput, std::move(finalResult));
    };
}

/***********************************/
// template<typename T>
// using resultFnHandler = std::function<void(T&)>; // This is a function that takes a T& and save the result
// template<typename T>
// using listResultFn = std::deque<resultFnHandler<T>>; // This is a list of resultFnHandler
/***********************************/

template<typename T>
struct Mergeable
{
    /**
     * @brief This is a function that takes a T& and a list of tokens and process the tokens
     * @details The function returns a tuple with a boolean that indicates if the process was successful
     * and an optional TraceP that contains the error message if the process was not successful
     */
    std::function<std::tuple<bool, std::optional<TraceP>>(T&, const std::deque<std::string_view>&)> m_semanticProcessor;
    T m_result;                            ///< The result of the semantic processor
    std::deque<std::string_view> m_tokens; ///< Store the tokens of the result the sintactic parser found
};

template<typename T>
using MergeableParser = Parser<Mergeable<T>>; // This is a parser that returns a Mergeable

template<typename T>
using MergeableResultP = ResultP<Mergeable<T>>; // This is a result of a MergeableParser


template<typename T>
Parser<T> merge(const std::list<MergeableParser<T>>& parsers)
{
    return [parsers](const InputP input) -> ResultP<T>
    {
        InputP currentInput = input;
        std::list<Mergeable<T>> mergeables;
        for (auto& parser : parsers)
        {
            auto result = parser(currentInput);
            if (!result)
            {
                if(result.hasTraces())
                {
                    return ResultP<T>::failure(TraceP("Fail parse sequence [Syntaictic fail]", currentInput.getPos()))
                        .concatenateTraces(std::move(result));
                }
                return ResultP<T>::failure();
            }
            if (result.hasValue())
            {
                mergeables.push_back(result.popValue().value());
            }
            currentInput = result.getRemaining();
        }

        // if all pre-parsers succeeded, process the tokens
        T finalResult;
        for (auto& mergeable : mergeables)
        {
            auto [success, optTrace] = mergeable.m_semanticProcessor(finalResult, mergeable.m_tokens);
            if (!success)
            {
                if (optTrace)
                {
                    return ResultP<T>::failure(TraceP("Fail parse sequence [Semantic fail]", 0))
                        .concatenateTraces(std::move(*optTrace));
                }
                return ResultP<T>::failure();
            }
        }
        return ResultP<T>::success(currentInput, std::move(finalResult));
    };

}
} // namespace combinator



// ******************************************************


/*****************************************************************************************
 * Test for the combinator::merge parser
 * ****************************************************************************************/
template<typename T>
using resultFnHandler = std::function<void(T&)>; // This is a function that takes a T& and save the result

template<typename T>
using listResultFn = std::deque<resultFnHandler<T>>; // This is a list of resultFnHandler

using fnList = listResultFn<json::Json>;
// parseQuotedString
// Parser para cadenas de texto entre comillas dobles
combinator::MergeableParser<fnList>
getParseQuotedString(const std::string& fieldName, bool enableCapure, bool enableTrace = false)
{

    auto path = json::Json::formatJsonPath(fieldName);

    // Semantic action
    auto m_semanticProcessor =
        [path](fnList& result, const std::deque<std::string_view>& tokens) -> std::tuple<bool, std::optional<TraceP>>
    {
        if (tokens.size() == 0)
        {
            return {true, std::nullopt};
        }

        result.push_back([path, value = std::string(tokens.front())](json::Json& json) { json.setString(value, path); });
        return {true, std::nullopt};
    };

    // Sintactic action
    return [m_semanticProcessor, enableCapure, enableTrace](InputP input) -> combinator::MergeableResultP<fnList>
    {
        if (input.getRemaining() == 0)
        {
            if (enableTrace)
            {
                return combinator::MergeableResultP<fnList>::failure(TraceP("EOS reached", input.getPos()));
            }
            return combinator::MergeableResultP<fnList>::failure();
        }

        auto inputStr = input.getRemainingData();

        if (inputStr.front() != '"')
        {
            if (enableTrace)
            {
                return combinator::MergeableResultP<fnList>::failure(
                    TraceP("Expected start with '\"'", input.getPos()));
            }
            return combinator::MergeableResultP<fnList>::failure();
        }

        bool isValidQuote = false;
        std::size_t offset = 1;
        // Search for the end the next '"' that is not escaped
        while (offset < inputStr.size())
        {
            if (inputStr[offset] == '"' && inputStr[offset - 1] != '\\')
            {
                isValidQuote = true;
                break;
            }
            offset++;
        }

        if (!isValidQuote)
        {
            if (enableTrace)
            {
                return combinator::MergeableResultP<fnList>::failure(
                    TraceP("Expected end '\"' but not found", input.getPos()));
            }
            return combinator::MergeableResultP<fnList>::failure();
        }

        if (enableCapure)
        {
            return combinator::MergeableResultP<fnList>::success(
                input.advance(offset + 1), {m_semanticProcessor, fnList(), {inputStr.substr(1, offset - 1)}});
        }
        return combinator::MergeableResultP<fnList>::success(input.advance(offset + 1),
                                                             {m_semanticProcessor, fnList(), {}});
    };
}

// Parse a IP
combinator::MergeableParser<fnList>
getParserIP(const std::string& fieldName, const std::string& endToken, bool enableCapure, bool enableTrace = false) {

        auto path = json::Json::formatJsonPath(fieldName);

        // Semantic action
        auto m_semanticProcessor =
            [path, enableCapure, enableTrace](fnList& result, const std::deque<std::string_view>& tokens) -> std::tuple<bool, std::optional<TraceP>>
        {
            // tokens.size() == 1
            auto srcip = std::string(tokens.front());

            // Check if the IP is valid
            struct in_addr ipv4;
            struct in6_addr ipv6;
            if (inet_pton(AF_INET, srcip.c_str(), &ipv4) || inet_pton(AF_INET6, srcip.c_str(), &ipv6))
            {
                if (enableCapure)
                {
                    result.push_back([path, value = std::move(srcip)](json::Json& json) { json.setString(value, path); });
                }
                return {true, std::nullopt};
            }
            if (enableTrace)
            {
                return {false, TraceP("Invalid IP address", 0)};
            }
            return {false, std::nullopt};

        };

        // Sintactic action
        return [m_semanticProcessor, endToken, enableTrace](InputP input) -> combinator::MergeableResultP<fnList>
        {
            if (input.getRemaining() == 0)
            {
                if (enableTrace)
                {
                    return combinator::MergeableResultP<fnList>::failure(TraceP("EOS reached", input.getPos()));
                }
                return combinator::MergeableResultP<fnList>::failure();
            }

            auto inputStr = input.getRemainingData();
            auto until = endToken.size() ? inputStr.find(endToken) : inputStr.length();
            if (until == std::string_view::npos)
            {
                if (enableTrace)
                {
                    return combinator::MergeableResultP<fnList>::failure(
                        TraceP("Expected end '" + endToken + "' but not found", input.getPos()));
                }
                return combinator::MergeableResultP<fnList>::failure();
            }
            auto IpCandidate = inputStr.substr(0, until);
            // Check long IP
            constexpr std::size_t IPv6Length = std::char_traits<char>::length("fd7a:115c:a1e0:ab12:4843:cd96:626d:1730");
            if (IpCandidate.size() > IPv6Length)
            {
                if (enableTrace)
                {
                    auto msg = "Invalid IP address: '" + std::string(IpCandidate) + "', is too long";
                    return combinator::MergeableResultP<fnList>::failure(TraceP(msg, input.getPos()));
                }
                return combinator::MergeableResultP<fnList>::failure();
            }

            // Add the IP to the result
            return combinator::MergeableResultP<fnList>::success(input.advance(until),
                                                                 {m_semanticProcessor, fnList(), {IpCandidate}});

        };

}

// Parse a Number
combinator::MergeableParser<fnList>
getParseNumber(const std::string& fieldName, bool enableCapure, bool enableTrace = false) {

        auto path = json::Json::formatJsonPath(fieldName);

        // Semantic action
        auto m_semanticProcessor =
            [path, enableCapure, enableTrace](fnList& result, const std::deque<std::string_view>& tokens) -> std::tuple<bool, std::optional<TraceP>>
        {
            // tokens.size() == 1
            auto number = std::string(tokens.front());

            // Convert to int
            try
            {
                auto value = std::stoi(number);
                if (enableCapure)
                {
                    result.push_back([path, value](json::Json& json) { json.setInt(value, path); });
                }
                return {true, std::nullopt};
            }
            catch (const std::invalid_argument& e)
            {
                if (enableTrace)
                {
                    return {false, TraceP("Invalid number: '" + number + "'", 0)};
                }
                return {false, std::nullopt};
            }
            catch (const std::out_of_range& e)
            {
                if (enableTrace)
                {
                    return {false, TraceP("Invalid number: '" + number + "' is out of range", 0)};
                }
                return {false, std::nullopt};
            }

            return {false, std::nullopt};

        };

        // Sintactic action
        return [m_semanticProcessor, enableTrace](InputP input) -> combinator::MergeableResultP<fnList>
        {
            if (input.getRemaining() == 0)
            {
                if (enableTrace)
                {
                    return combinator::MergeableResultP<fnList>::failure(TraceP("EOS reached", input.getPos()));
                }
                return combinator::MergeableResultP<fnList>::failure();
            }

            auto inputStr = input.getRemainingData();
            // Check if the number is valid
            auto until = inputStr.find_first_not_of("0123456789", inputStr[0] == '-' ? 1 : 0);
            if (until == std::string_view::npos)
            {
                until = inputStr.length();
            } else if (until == 0)
            {
                if (enableTrace)
                {
                    return combinator::MergeableResultP<fnList>::failure(
                        TraceP("Invalid number: '" + std::string(inputStr) + "'", input.getPos()));
                }
                return combinator::MergeableResultP<fnList>::failure();
            }
            auto numberCandidate = inputStr.substr(0, until);

            // Add the number to the result
            return combinator::MergeableResultP<fnList>::success(input.advance(until),
                                                                 {m_semanticProcessor, fnList(), {numberCandidate}});
        };
}

// Parse any string
combinator::MergeableParser<fnList>
getParserAny(const std::string& fieldName, const std::string& endToken, bool enableCapure, bool enableTrace = false)
{
    auto path = json::Json::formatJsonPath(fieldName);

    // Semantic action
    auto m_semanticProcessor =
        [path, enableCapure, enableTrace](fnList& result, const std::deque<std::string_view>& tokens) -> std::tuple<bool, std::optional<TraceP>>
    {
        if (enableCapure)
        {
            auto value = std::string(tokens.front());
            result.push_back([path, value](json::Json& json) { json.setString(value, path); });
        }
        return {true, std::nullopt};
    };

    // Sintactic action
    return [m_semanticProcessor, endToken, enableTrace](InputP input) -> combinator::MergeableResultP<fnList>
    {
        if (input.getRemaining() == 0)
        {
            if (enableTrace)
            {
                return combinator::MergeableResultP<fnList>::failure(TraceP("EOS reached", input.getPos()));
            }
            return combinator::MergeableResultP<fnList>::failure();
        }

        auto inputStr = input.getRemainingData();

        auto until = endToken.size() ? inputStr.find(endToken) : inputStr.length();
        if (until == std::string_view::npos)
        {
            if (enableTrace)
            {
                return combinator::MergeableResultP<fnList>::failure(
                    TraceP("Expected end '" + endToken + "' but not found", input.getPos()));
            }
            return combinator::MergeableResultP<fnList>::failure();
        }
        auto valueCandidate = inputStr.substr(0, until);

        // Add the value to the result
        return combinator::MergeableResultP<fnList>::success(input.advance(until),
                                                             {m_semanticProcessor, fnList(), {valueCandidate}});
    };
}


// Parse literal
combinator::MergeableParser<fnList>
getParseLiteral(const std::string& fieldName, const std::string& literal, bool enableCapure, bool enableTrace = false)
{
    auto path = json::Json::formatJsonPath(fieldName);

    if (literal.empty())
    {
        throw std::invalid_argument("Literal cannot be empty");
    }

    // Semantic action
    auto m_semanticProcessor =
        [path, enableTrace](fnList& result, const std::deque<std::string_view>& tokens) -> std::tuple<bool, std::optional<TraceP>>
    {
        if (tokens.size() == 1) {
            auto value = std::string(tokens.front());
            result.push_back([path, value](json::Json& json) { json.setString(value, path); });
        }
        return {true, std::nullopt};
    };

    // Sintactic action
    return [m_semanticProcessor, literal, enableTrace, enableCapure](InputP input) -> combinator::MergeableResultP<fnList>
    {
        if (input.getRemaining() == 0)
        {
            if (enableTrace)
            {
                return combinator::MergeableResultP<fnList>::failure(TraceP("EOS reached", input.getPos()));
            }
            return combinator::MergeableResultP<fnList>::failure();
        }

        auto inputStr = input.getRemainingData();

        // Compare the literal
        if (inputStr.substr(0, literal.size()) != literal)
        {
            if (enableTrace)
            {
                return combinator::MergeableResultP<fnList>::failure(
                    TraceP("Expected literal '" + literal + "' but found " + std::string(inputStr), input.getPos()));
            }
            return combinator::MergeableResultP<fnList>::failure();
        }

        if (enableCapure)
        {
            // Add the value to the result
            return combinator::MergeableResultP<fnList>::success(input.advance(literal.size()),
                                                                 {m_semanticProcessor, fnList(), {literal}});
        }
        return combinator::MergeableResultP<fnList>::success(input.advance(literal.size()),
                                                             {m_semanticProcessor, fnList(), {}});

    };
}




} // namespace hlp3::parser

#endif // _HLP3_HLP3_HPP
