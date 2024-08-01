#ifndef _HLP_PARSER_HPP
#define _HLP_PARSER_HPP

#include <functional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <fmt/format.h>
#include <base/json.hpp>

#include "abstractParser.hpp"

/**
 * @brief Contains the Parser and Results types used by HLP.
 *
 */
namespace hlp::parser
{
// Mapper functions dont check
using Mapper = std::function<void(json::Json&)>;

/**
 * @brief Empty mapper function, used when a parser has semantic parser but it is told to not map.
 *
 * @return Mapper
 */
inline Mapper noMapper()
{
    return [](json::Json&) {
    };
}
using SemParser = std::function<std::variant<Mapper, base::Error>(std::string_view)>;
struct SemToken
{
    std::string_view parsed;
    SemParser semParser;
};

/**
 * @brief Empty semantic parser function, used when a parser has no semantic parser and it is told to not map.
 *
 * @return SemParser
 */
inline SemParser noSemParser()
{
    return [](std::string_view) -> std::variant<Mapper, base::Error>
    {
        return noMapper();
    };
}

using ResultT = SemToken;
using Result = abs::Result<ResultT>;
using Parser = abs::Parser<ResultT>;

/**
 * @brief Runs three steps of parsing: syntax, semantic and mapping. Returns an error if any of the steps fails at any
 * point.
 *
 * @param parser Parser to run
 * @param text Text to parse
 * @param event Event to map to
 * @return std::optional<base::Error>
 */
inline std::optional<base::Error> run(const Parser& parser, std::string_view text, json::Json& event)
{
    // Syntax parsing
    auto synRes = parser(text);
    if (synRes.failure())
    {
        const auto error = fmt::format("Parser {} failed at: {}", synRes.trace(), synRes.remaining());
        return base::Error {error};
    }

    // Semantinc parsing
    std::vector<Mapper> mappers;
    auto semVisitor = [&mappers](const Result& result, auto& recurRef) -> std::optional<base::Error>
    {
        if (result.hasValue())
        {
            auto res = result.value().semParser(result.value().parsed);
            if (std::holds_alternative<base::Error>(res))
            {
                return std::get<base::Error>(res);
            }

            mappers.emplace_back(std::get<Mapper>(std::move(res)));
        }

        for (const auto& child : result.nested())
        {
            auto error = recurRef(child, recurRef);
            if (error)
            {
                return std::move(error);
            }
        }

        return std::nullopt;
    };

    auto error = semVisitor(synRes, semVisitor);
    if (error)
    {
        return std::move(error);
    }

    // Mappings
    for (const auto& mapper : mappers)
    {
        mapper(event);
    }

    return std::nullopt;
}

/**
 * @brief Combinators used by HLP.
 *
 */
namespace combinator
{
inline Parser choice(const Parser& lhs, const Parser& rhs)
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

        return abs::makeFailure<ResultT>(input, "choice: both failed");
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

inline Parser all(const std::vector<Parser>& parsers)
{
    return [parsers](std::string_view input) -> Result
    {
        auto remaining = input;
        Result::Nested results;

        for (const auto& parser : parsers)
        {
            auto result = parser(remaining);
            if (result.failure())
            {
                return std::move(result);
            }

            remaining = result.remaining();
            results.emplace_back(std::move(result));
        }

        return abs::makeSuccess<ResultT>(remaining, std::move(results));
    };
}
} // namespace combinator
} // namespace hlp::parser

#endif // _HLP_PARSER_HPP
