#ifndef _BUILDER_HELPER_PARSER_HPP
#define _BUILDER_HELPER_PARSER_HPP

#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include <fmt/format.h>
#include <re2/re2.h>

#include <error.hpp>
#include <json/json.hpp>

#include "syntax.hpp"
#include "utils/stringUtils.hpp"

#include <parsec/parsec.hpp>

namespace builder::internals
{

/**
 * @brief Token representing a helper function
 *
 * @details Helper function is represented by a name and a list of arguments.
 *
 */
struct HelperToken
{
    std::string name = "";
    std::vector<std::string> args = {};

    friend std::ostream& operator<<(std::ostream& os, const HelperToken& helperToken)
    {
        std::string separator {};
        separator += syntax::FUNCTION_HELPER_ARG_ANCHOR;

        os << helperToken.name << "(" << base::utils::string::join(helperToken.args, separator, false) << ")";

        return os;
    }
};

/**
 * @brief Obtain builder input parameters from helper token
 *
 * @param helperToken Token representing a helper function
 * @param targetField Target field for the helper function
 * @return std::tuple<std::string, json::Json>
 */
inline std::tuple<std::string, json::Json> toBuilderInput(const HelperToken& helperToken,
                                                          const std::string& targetField)
{
    json::Json value {};
    auto valueStr = fmt::format("{}({})", helperToken.name, base::utils::string::join(helperToken.args, ","));
    value.setString(valueStr);

    return std::make_tuple(targetField, std::move(value));
}

/**
 * @brief Obtain builder input parameters from helper token, where the first argument is the target field
 *
 * @param helperToken Token representing a helper function
 * @return std::tuple<std::string, json::Json>
 */
inline std::tuple<std::string, json::Json> toBuilderInput(const HelperToken& helperToken)
{
    if (helperToken.args.empty() || helperToken.args[0].empty())
    {
        std::stringstream ss {};
        ss << helperToken;
        throw std::runtime_error(
            fmt::format("Helper {} has no arguments, expected to have target field as first argument", ss.str()));
    }
    else if (helperToken.args[0][0] != syntax::REFERENCE_ANCHOR)
    {
        std::stringstream ss {};
        ss << helperToken;
        throw std::runtime_error(fmt::format("Helper {} has no target field as first argument", ss.str()));
    }

    // Remove reference anchor
    return toBuilderInput({helperToken.name, {helperToken.args.begin() + 1, helperToken.args.end()}},
                          helperToken.args[0].substr(1));
}

// operators (==, !=, <, >, <=, >=)
enum class ExpressionOperator
{
    EQUAL,
    NOT_EQUAL,
    GREATER_THAN,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN,
    LESS_THAN_OR_EQUAL
};

/**
 * @brief Token representing an expression
 *
 * @details Expression is represented by a field, an operator and a value.
 *
 */
struct ExpressionToken
{
    std::string field;
    ExpressionOperator op;
    json::Json value;
};

/**
 * @brief Obtain builder input parameters from expression token
 *
 * @param expressionToken Token representing an expression
 * @return std::tuple<std::string, json::Json>
 */
inline std::tuple<std::string, json::Json> toBuilderInput(const ExpressionToken& expressionToken)
{
    if (expressionToken.field.empty())
    {
        throw std::runtime_error("Expression field is empty");
    }

    if (expressionToken.op == ExpressionOperator::EQUAL)
    {
        return std::make_tuple(expressionToken.field.substr(1), expressionToken.value);
    }

    if (expressionToken.op == ExpressionOperator::NOT_EQUAL && !expressionToken.value.isString()
        && !expressionToken.value.isNumber())
    {
        throw std::runtime_error("Not equal operator is not supported for non string or number values");
    }

    // Rest of operators only support string or number values
    if (!expressionToken.value.isString() && !expressionToken.value.isNumber())
    {
        throw std::runtime_error("Expression value is not string or number");
    }

    HelperToken helperToken {};

    if (expressionToken.value.isNumber())
    {
        helperToken.name = "int";
        helperToken.args = {std::to_string(expressionToken.value.getInt().value())};
    }
    else
    {
        helperToken.name = "string";
        helperToken.args = {expressionToken.value.getString().value()};
    }

    switch (expressionToken.op)
    {
        case ExpressionOperator::GREATER_THAN: helperToken.name += "_greater"; break;
        case ExpressionOperator::GREATER_THAN_OR_EQUAL: helperToken.name += "_greater_or_equal"; break;
        case ExpressionOperator::LESS_THAN: helperToken.name += "_less"; break;
        case ExpressionOperator::LESS_THAN_OR_EQUAL: helperToken.name += "_less_or_equal"; break;
        case ExpressionOperator::NOT_EQUAL: helperToken.name += "_not_equal"; break;
        default: throw std::logic_error("Unknown expression operator");
    }

    return toBuilderInput(helperToken, expressionToken.field.substr(1));
}

using BuildToken = std::variant<HelperToken, ExpressionToken>;

/**
 * @brief Get a parser that parses a helper function
 *
 * @return parsec::Parser<HelperToken>
 */
inline parsec::Parser<HelperToken> getHelperParser(bool eraseScapeChars = false)
{
    std::string helperExtended = syntax::HELPER_NAME_EXTENDED;
    parsec::Parser<std::string> helperNameParser = [helperExtended](auto sv, auto pos) -> parsec::Result<std::string>
    {
        auto next = pos;
        while (next < sv.size() && (std::isalnum(sv[next]) || helperExtended.find(sv[next]) != std::string::npos))
        {
            ++next;
        }

        if (next == pos)
        {
            return parsec::makeError<std::string>("Empty helper name", pos);
        }

        return parsec::makeSuccess(std::string(sv.substr(pos, next - pos)), next);
    };

    parsec::Parser<std::string> parenthOpenParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (sv[pos] != syntax::PARENTHESIS_OPEN)
        {
            return parsec::makeError<std::string>("Parenthesis open expected", pos);
        }
        // Skip whitespace
        auto next = pos + 1;
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        return parsec::makeSuccess(std::string(1, syntax::PARENTHESIS_OPEN), next);
    };

    parsec::Parser<std::string> behindParenthCloseParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (pos == 0 || sv[pos - 1] != syntax::PARENTHESIS_CLOSE)
        {
            return parsec::makeError<std::string>("Parenthesis close expected", pos);
        }

        return parsec::makeSuccess(std::string(1, syntax::PARENTHESIS_CLOSE), pos);
    };

    parsec::Parser<std::string> argParser = [eraseScapeChars](auto sv, auto pos) -> parsec::Result<std::string>
    {
        auto next = pos;
        auto arg = std::string();

        if (next >= sv.size())
        {
            return parsec::makeError<std::string>("EOA", pos);
        }

        // Unescape \$ at the beginning of the parameter
        if (next + 1 < sv.size() && sv[next] == syntax::FUNCTION_HELPER_DEFAULT_ESCAPE && sv[next + 1] == syntax::REFERENCE_ANCHOR)
        {
            arg += '\\';
            ++next;
        }

        for (; next < sv.size(); ++next)
        {
            // Check for end of argument
            if (sv[next] == syntax::FUNCTION_HELPER_ARG_ANCHOR || sv[next] == syntax::PARENTHESIS_CLOSE)
            {
                break;
            }
            // Check for escape sequence
            else if (sv[next] == syntax::FUNCTION_HELPER_DEFAULT_ESCAPE)
            {
                if (next + 1 < sv.size())
                {
                    // Expecting escapeable character
                    if (sv[next + 1] == syntax::FUNCTION_HELPER_ARG_ANCHOR || sv[next + 1] == syntax::PARENTHESIS_CLOSE
                        || sv[next + 1] == syntax::FUNCTION_HELPER_DEFAULT_ESCAPE || std::isspace(sv[next + 1]))
                    {
                        if (!eraseScapeChars)
                        {
                            arg += sv[next];
                        }
                        ++next;
                    }
                    else
                    {
                        return parsec::makeError<std::string>("Invalid escape sequence", next);
                    }
                }
                else
                {
                    return parsec::makeError<std::string>("Invalid escape sequence", next);
                }
            }

            arg += sv[next];
        }

        return parsec::makeSuccess(std::move(arg), next);
    };

    parsec::Parser<std::string> endArgParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        parsec::Result<std::string> res;
        auto next = pos;
        if (sv[next] == syntax::FUNCTION_HELPER_ARG_ANCHOR)
        {
            // Optional whitespaces (TODO check case ( a    , c    ))
            ++next;
            while (next < sv.size() && std::isspace(sv[next]))
            {
                ++next;
            }

            res = parsec::makeSuccess(std::string(sv.substr(pos, next - pos)), next);
        }
        else if (sv[next] == syntax::PARENTHESIS_CLOSE)
        {
            res = parsec::makeSuccess(std::string(sv.substr(pos, 1)), pos + 1);
        }
        else
        {
            res = parsec::makeError<std::string>("Argument separator or parenthesis close expected", pos);
        }

        return res;
    };

    auto helperArgsParser = parsec::many1(parsec::negativeLook(behindParenthCloseParser) >> argParser << endArgParser);
    auto helperParserRaw =
        (helperNameParser << parenthOpenParser) & (helperArgsParser << parsec::positiveLook(behindParenthCloseParser));
    auto helperParser = parsec::fmap<HelperToken, std::tuple<std::string, parsec::Values<std::string>>>(
        [](auto&& tuple) -> HelperToken
        {
            HelperToken helperToken;
            helperToken.name = std::get<0>(tuple);
            helperToken.args = std::vector<std::string>(std::get<1>(tuple).begin(), std::get<1>(tuple).end());
            // When empty args parser returns one empty string
            if (helperToken.args.size() == 1 && helperToken.args[0].empty())
            {
                helperToken.args.clear();
            }

            return helperToken;
        },
        helperParserRaw);

    return helperParser;
}

/**
 * @brief Get a parser that parses a expression
 *
 * @return parsec::Parser<ExpressionToken>
 */
inline parsec::Parser<ExpressionToken> getExpressionParser()
{
    parsec::Parser<json::Json> jsonParser = [](auto sv, auto pos) -> parsec::Result<json::Json>
    {
        if (sv.size() <= pos)
        {
            return parsec::makeError<json::Json>("Empty json", pos);
        }

        rapidjson::Reader reader;
        rapidjson::StringStream ss(sv.substr(pos).data());
        rapidjson::Document doc;

        doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(ss);
        if (doc.HasParseError())
        {
            return parsec::makeError<json::Json>("Error parsing json", pos);
        }

        return parsec::makeSuccess(json::Json(std::move(doc)), pos + ss.Tell());
    };

    parsec::Parser<std::string> fieldParser =
        [fieldExtended = std::string(syntax::FIELD_EXTENDED) + syntax::JSON_PATH_SEPARATOR
                         + syntax::FUNCTION_HELPER_DEFAULT_ESCAPE](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (sv[pos] != syntax::REFERENCE_ANCHOR)
        {
            return parsec::makeError<std::string>("Reference expected", pos);
        }

        auto next = pos + 1;

        while (next < sv.size()
               && (std::isalnum(sv[next]) || fieldExtended.find(sv[next]) != std::string::npos))
        {
            ++next;
        }

        if (next == pos + 1)
        {
            return parsec::makeError<std::string>("Empty reference", pos);
        }

        return parsec::makeSuccess(std::string(sv.substr(pos, next - pos)), next);
    };

    parsec::Parser<json::Json> valueRefParser = parsec::fmap<json::Json, std::string>(
        [](auto&& str) -> json::Json
        {
            json::Json value;
            value.setString(str);
            return std::move(value);
        },
        fieldParser);

    parsec::Parser<json::Json> wordParser = [](auto sv, auto pos) -> parsec::Result<json::Json>
    {
        auto next = pos;
        while (next < sv.size() && !std::isspace(sv[next]))
        {
            ++next;
        }

        if (next == pos)
        {
            return parsec::makeError<json::Json>("Empty word", pos);
        }

        json::Json word;
        word.setString(sv.substr(pos, next - pos));
        return parsec::makeSuccess(std::move(word), next);
    };

    auto valueParser = valueRefParser | jsonParser | wordParser;

    parsec::Parser<ExpressionOperator> operatorParser = [](auto sv, auto pos) -> parsec::Result<ExpressionOperator>
    {
        auto next = pos;

        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        if (next + 1 > sv.size())
        {
            return parsec::makeError<ExpressionOperator>("Operator expected", pos);
        }

        std::vector<std::pair<std::string_view, ExpressionOperator>> compareList = {
            {"==", ExpressionOperator::EQUAL},
            {"!=", ExpressionOperator::NOT_EQUAL},
            {"<=", ExpressionOperator::LESS_THAN_OR_EQUAL},
            {">=", ExpressionOperator::GREATER_THAN_OR_EQUAL},
            {"<", ExpressionOperator::LESS_THAN},
            {">", ExpressionOperator::GREATER_THAN},
        };

        ExpressionOperator op;
        bool found = false;
        for (auto&& compare : compareList)
        {
            if (sv.substr(next, compare.first.size()) == compare.first)
            {
                op = compare.second;
                next += compare.first.size();
                found = true;
                break;
            }
        }

        if (!found)
        {
            return parsec::makeError<ExpressionOperator>("Unknown operator", pos);
        }

        // Ignore spaces after operator
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        return parsec::makeSuccess(std::move(op), next);
    };

    // <$field><op><value>
    // $field==word
    // $field==$ref
    // $field=="json"

    parsec::Parser<ExpressionToken> expressionParser =
        parsec::fmap<ExpressionToken, std::tuple<std::tuple<std::string, ExpressionOperator>, json::Json>>(
            [](auto&& tuple) -> ExpressionToken
            {
                ExpressionToken expressionToken;
                expressionToken.field = std::get<0>(std::get<0>(tuple));
                expressionToken.op = std::get<1>(std::get<0>(tuple));
                expressionToken.value = std::move(std::get<1>(tuple));
                return std::move(expressionToken);
            },
            fieldParser& operatorParser& valueParser);

    return expressionParser;
}

/**
 * @brief Get a parsec::Parser that parses a logicexpr term, where a term is a helper function or an expression
 *
 * @return parsec::Parser<BuildToken>
 */
inline parsec::Parser<BuildToken> getTermParser()
{
    auto helperParser = getHelperParser();
    auto expressionParser = getExpressionParser();

    parsec::Parser<BuildToken> helperParserToken = parsec::fmap<BuildToken, HelperToken>(
        [](auto&& helperToken) -> BuildToken { return std::move(helperToken); }, helperParser);
    parsec::Parser<BuildToken> expressionParserToken = parsec::fmap<BuildToken, ExpressionToken>(
        [](auto&& expressionToken) -> BuildToken { return std::move(expressionToken); }, expressionParser);

    parsec::Parser<BuildToken> parser = helperParserToken | expressionParserToken;

    return parser;
}

/**
 * @brief Parses a helper function string
 *
 * @param sv string to parse
 * @return std::variant<HelperToken, base::Error> HelperToken if success, Error otherwise
 */
inline std::variant<HelperToken, base::Error> parseHelper(std::string_view sv)
{
    auto helperParser = getHelperParser(true);
    auto result = helperParser(sv, 0);

    if (result.failure())
    {
        return base::Error {result.error()};
    }

    if (result.index() != sv.size())
    {
        return base::Error {"Expected end of string"};
    }

    return result.value();
}
} // namespace builder::internals

#endif // _BUILDER_HELPER_PARSER_HPP
