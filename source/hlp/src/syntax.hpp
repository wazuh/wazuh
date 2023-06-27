#ifndef _HLP_SYNTAX_HPP
#define _HLP_SYNTAX_HPP

#include <algorithm>
#include <stdexcept>

#include "abstractParser.hpp"

/**
 * @brief Contains the Parser and Result types for the syntax parsers
 *
 */
namespace hlp::syntax
{
using ResultT = std::string_view;
using Result = abs::Result<ResultT>;
using Parser = abs::Parser<ResultT>;

/**
 * @brief Given a syntax parser result and the original input, returns the parsed string.
 *
 * @param result
 * @param original
 * @return std::string_view
 */
inline std::string_view parsed(const Result& result, std::string_view original)
{
    return original.substr(0, original.size() - result.remaining().size());
}

/**
 * @brief Contains the combinators for the syntax parsers, this combinators do not extract any value and do not nest the
 * results.
 *
 */
namespace combinators
{
inline Parser operator&(const Parser& lhs, const Parser& rhs)
{
    return [lhs, rhs](std::string_view input) -> Result
    {
        auto resultL = lhs(input);
        if (resultL.failure())
        {
            return std::move(resultL);
        }

        auto resultR = rhs(resultL.remaining());
        if (resultR.failure())
        {
            return std::move(resultR);
        }

        return abs::makeSuccess<ResultT>(resultR.remaining());
    };
}

inline Parser operator|(const Parser& lhs, const Parser& rhs)
{
    return [lhs, rhs](std::string_view input) -> Result
    {
        auto resultL = lhs(input);
        if (resultL.success())
        {
            return std::move(resultL);
        }

        auto resultR = rhs(input);
        if (resultR.success())
        {
            return std::move(resultR);
        }

        return abs::makeFailure<ResultT>(input, {});
    };
}

inline Parser opt(const Parser& parser)
{
    return [parser](std::string_view input) -> Result
    {
        auto result = parser(input);
        if (result.success())
        {
            return std::move(result);
        }

        return abs::makeSuccess<ResultT>(input);
    };
}

inline Parser times(const Parser& parser, size_t min = 0, size_t max = 0)
{
    return [parser, min, max](std::string_view input) -> Result
    {
        auto matched = 0;
        auto remaining = input;

        do
        {
            auto result = parser(remaining);
            if (result.failure())
            {
                break;
            }

            remaining = result.remaining();
            ++matched;
        } while (matched < max | max == 0);

        if (matched < min)
        {
            return abs::makeFailure<ResultT>(input, {});
        }

        return abs::makeSuccess<ResultT>(remaining);
    };
}

inline Parser many(const Parser& parser)
{
    return times(parser);
}

inline Parser many1(const Parser& parser)
{
    return times(parser, 1);
}

inline Parser repeat(const Parser& parser, size_t count)
{
    return times(parser, count, count);
}

} // namespace combinators

/**
 * @brief Basic parsers for the syntax parsers, this parsers do not extract any value and do not nest the results.
 *
 */
namespace parsers
{

/**
 * @brief Matches any character, if the input is empty returns a failure.
 *
 * @return Parser
 */
inline Parser any()
{
    return [](std::string_view input) -> Result
    {
        if (input.empty())
        {
            return abs::makeFailure<ResultT>(input, {});
        }

        return abs::makeSuccess<ResultT>(input.substr(1));
    };
}

/**
 * @brief Matches the given character, if the input is empty or the first character is not the given one returns a
 * failure.
 *
 * @param c
 * @return Parser
 */
inline Parser char_(char c)
{
    return [c](std::string_view input) -> Result
    {
        if (input.empty() || input[0] != c)
        {
            return abs::makeFailure<ResultT>(input, {});
        }

        return abs::makeSuccess<ResultT>(input.substr(1));
    };
}

/**
 * @brief Matches any digit, if the input is empty or the first character is not a digit returns a failure.
 *
 * @return Parser
 */
inline Parser digit()
{
    return [](std::string_view input) -> Result
    {
        if (input.empty() || !std::isdigit(input[0]))
        {
            return abs::makeFailure<ResultT>(input, {});
        }

        return abs::makeSuccess<ResultT>(input.substr(1));
    };
}

/**
 * @brief Matches the given literal
 *
 * @param lit The literal to match
 * @param caseSensitive If true, the literal is case sensitive
 * @return Parser
 */
inline Parser literal(const std::string lit, bool caseSensitive = true)
{
    if (caseSensitive)
    {
        return [lit](std::string_view input) -> Result
        {
            if (input.empty() || input.substr(0, lit.size()) != lit)
            {
                return abs::makeFailure<ResultT>(input, {});
            }

            return abs::makeSuccess<ResultT>(input.substr(lit.size()));
        };
    }
    else
    {
        auto lowerLit = lit;
        std::transform(lowerLit.begin(), lowerLit.end(), lowerLit.begin(), [](char c) { return std::tolower(c); });
        return [lowerLit](std::string_view input) -> Result
        {
            if (input.size() < lowerLit.size())
            {
                return abs::makeFailure<ResultT>(input, {});
            }

            for (auto i = 0; i < lowerLit.size(); ++i)
            {
                if (std::tolower(input[i]) != lowerLit[i])
                {
                    return abs::makeFailure<ResultT>(input, {});
                }
            }

            return abs::makeSuccess<ResultT>(input.substr(lowerLit.size()));
        };
    }
}

/**
 * @brief Matches any input up to the given character without consuming the character. If the input is empty returns a
 * failure.
 *
 * @param endToken
 * @return Parser
 */
inline Parser toEnd(char endToken)
{
    return [endToken](std::string_view input) -> Result
    {
        const auto pos = input.find(endToken);
        if (pos == std::string_view::npos || pos == 0)
        {
            return abs::makeFailure<ResultT>(input, {});
        }

        return abs::makeSuccess<ResultT>(input.substr(pos));
    };
}

/**
 * @brief Matches any input up to the given string without consuming the string. If the input is empty returns a
 * failure.
 *
 * @param endToken
 * @return Parser
 */
inline Parser toEnd(const std::string& endToken)
{
    return [endToken](std::string_view input) -> Result
    {
        const auto pos = input.find(endToken);
        if (pos == std::string_view::npos || pos == 0)
        {
            return abs::makeFailure<ResultT>(input, {});
        }

        return abs::makeSuccess<ResultT>(input.substr(pos));
    };
}

/**
 * @brief Matches until the end of the input. If the input is empty returns a failure.
 *
 * @return Parser
 */
inline Parser toEnd()
{
    return [](std::string_view input) -> Result
    {
        if (input.empty())
        {
            return abs::makeFailure<ResultT>(input, {});
        }

        return abs::makeSuccess<ResultT>(input.substr(input.size()));
    };
}

/**
 * @brief For each endToken, build a parser that matches until the endToken is found. If the endToken is empty, matches
 * until the end of the input. Returns a parser that matches if any of the endToken parsers matches.
 *
 * @param endTokens
 * @return Parser
 */
inline Parser toEnd(const std::vector<std::string>& endTokens)
{
    using namespace combinators;

    if (endTokens.empty())
    {
        throw std::runtime_error("endTokens must not be empty");
    }

    Parser p;
    if (endTokens[0].empty())
    {
        p = toEnd();
    }
    else
    {
        p = toEnd(endTokens[0]);
    }

    for (auto it = endTokens.begin() + 1; it != endTokens.end(); ++it)
    {
        Parser next;
        if (it->empty())
        {
            next = toEnd();
        }
        else
        {
            next = toEnd(*it);
        }

        p = p | next;
    }

    return p;
}

/**
 * @brief Matches an alphanumeric character. If the input is empty or the first character is not alphanumeric returns a
 * failure.
 *
 * @param additional String containing additional allowed characters
 * @return Parser
 */
inline Parser alnum(const std::string& additional = "")
{
    return [additional](std::string_view input) -> Result
    {
        if (!input.empty() && (std::isalnum(input[0]) || additional.find(input[0]) != std::string::npos))
        {
            return abs::makeSuccess<ResultT>(input.substr(1));
        }
        return abs::makeFailure<ResultT>(input, {});
    };
}

/**
 * @brief Matches a hexadecimal character. If the input is empty or the first character is not hexadecimal returns a
 * failure.
 *
 * @return Parser
 */
inline Parser hex()
{
    return [](std::string_view input) -> Result
    {
        if (input.empty() || !std::isxdigit(input[0]))
        {
            return abs::makeFailure<ResultT>(input, {});
        }

        return abs::makeSuccess<ResultT>(input.substr(1));
    };
}

} // namespace parsers
} // namespace hlp::syntax

#endif // _HLP_SYNTAX_HPP
