#ifndef _HLP_SYNTAX_HPP
#define _HLP_SYNTAX_HPP

#include <algorithm>
#include <stdexcept>

#include "abstractParser.hpp"

namespace hlp::syntax
{
using ResultT = std::string_view;
using Result = abs::Result<ResultT>;
using Parser = abs::Parser<ResultT>;

inline std::string_view parsed(const Result& result, std::string_view original)
{
    return original.substr(0, original.size() - result.remaining().size());
}

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

namespace parsers
{

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

inline Parser alnum()
{
    return [](std::string_view input) -> Result
    {
        if (input.empty() || !std::isalnum(input[0]))
        {
            return abs::makeFailure<ResultT>(input, {});
        }

        return abs::makeSuccess<ResultT>(input.substr(1));
    };
}

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
