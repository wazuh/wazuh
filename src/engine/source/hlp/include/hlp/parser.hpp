#ifndef _HLP_PARSER_HPP
#define _HLP_PARSER_HPP

#include <functional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

#include <base/json.hpp>
#include <fmt/format.h>

#include "abstractParser.hpp"

/**
 * @brief Contains the Parser and Results types used by HLP.
 *
 */
namespace hlp::parser
{
using Mapper = std::function<void(json::Json&)>; ///< Maps parsed data into a JSON event.

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
using SemParser = std::function<std::variant<Mapper, base::Error>(std::string_view)>; ///< Semantic parser: validates parsed text and returns a Mapper or Error.

/**
 * @brief Token produced by the syntax parsing phase.
 */
struct SemToken
{
    std::string_view parsed; ///< The substring consumed by the syntax parser.
    SemParser semParser;     ///< The semantic parser for this token.
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

using ResultT = SemToken;              ///< Result value type for HLP parsers.
using Result = abs::Result<ResultT>;   ///< HLP parser result type.
using Parser = abs::Parser<ResultT>;   ///< HLP parser type.

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
/**
 * @brief HLP-level parser combinators.
 */
namespace combinator
{
/**
 * @brief Try the left parser first; if it fails, try the right parser.
 *
 * @param lhs Left parser.
 * @param rhs Right parser.
 * @return Parser A parser that succeeds if either parser succeeds.
 */
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

/**
 * @brief Make a parser optional. Always succeeds.
 *
 * @param parser The parser to wrap.
 * @return Parser A parser that always succeeds.
 */
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

/**
 * @brief Sequence combinator: run all parsers in order, fail if any fails.
 *
 * @param parsers Vector of parsers to run sequentially.
 * @return Parser A parser that succeeds if all parsers succeed.
 */
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
