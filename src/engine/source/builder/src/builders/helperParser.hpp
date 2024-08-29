#ifndef _BUILDER_HELPER_PARSER_HPP
#define _BUILDER_HELPER_PARSER_HPP

#include <iostream>
#include <string>
#include <tuple>
#include <variant>
#include <vector>

#include <fmt/format.h>
#include <rapidjson/document.h>
#include <rapidjson/stringbuffer.h>

#include <base/error.hpp>
#include <base/json.hpp>
#include <parsec/parsec.hpp>

#include "syntax.hpp"
#include "types.hpp"

namespace builder::builders::parsers
{
/******************************************************************************/
/* Helper function parsers */
/******************************************************************************/

/**
 * @brief Token representing a helper function
 *
 * @details Helper function is represented by a name and a list of arguments.
 *
 */
struct HelperToken
{
    std::string name = "";                  ///< Name of the helper function
    builders::Reference targetField;        ///< Target field for the helper function
    std::vector<builders::OpArg> args = {}; ///< Arguments for the helper function

    friend std::ostream& operator<<(std::ostream& os, const HelperToken& helperToken)
    {
        std::string separator {};
        separator += syntax::helper::ARG_ANCHOR;

        // TODO implement
        // os << helperToken.name << "(" << base::utils::string::join(helperToken.args, separator, false) << ")";

        return os;
    }
};

/**
 * @brief Parser for a single argument of a helper function between single quotes, always returns a string value
 *
 * @return parsec::Parser<builders::OpArg>
 */
inline parsec::Parser<builders::OpArg> getHelperQuotedArgParser()
{
    std::string reservedChars;
    reservedChars += syntax::helper::DEFAULT_ESCAPE;
    reservedChars += syntax::helper::SINGLE_QUOTE;
    return [reservedChars](auto sv, auto pos)
    {
        if (pos >= sv.size() || sv[pos] != syntax::helper::SINGLE_QUOTE)
        {
            return parsec::makeError<builders::OpArg>("Single quote expected", pos);
        }

        std::string rawStr;
        auto next = pos + 1;
        while (next < sv.size())
        {
            if (sv[next] == syntax::helper::SINGLE_QUOTE)
            {
                break;
            }

            if (sv[next] == syntax::helper::DEFAULT_ESCAPE)
            {
                if (next + 1 < sv.size() && reservedChars.find(sv[next + 1]) != std::string::npos)
                {
                    // Normal escape sequence
                    ++next;
                }
                else
                {
                    return parsec::makeError<builders::OpArg>("Invalid escape sequence", next + 1);
                }
            }

            rawStr += sv[next];
            ++next;
        }

        if (next == sv.size())
        {
            return parsec::makeError<builders::OpArg>("Missing end quote", next);
        }

        json::Json value;
        value.setString(std::move(rawStr));

        return parsec::makeSuccess<builders::OpArg>(std::make_shared<builders::Value>(std::move(value)), next + 1);
    };
}

/**
 * @brief Parser for a single argument of a helper function that is a reference
 *
 * @return parsec::Parser<builders::OpArg>
 */
inline parsec::Parser<builders::OpArg> getHelperRefArgParser()
{
    std::string extendedChars(syntax::field::NAME_EXTENDED);
    extendedChars += syntax::field::SEPARATOR;
    return [extendedChars](auto sv, auto pos) -> parsec::Result<builders::OpArg>
    {
        if (pos >= sv.size() || sv[pos] != syntax::field::REF_ANCHOR)
        {
            return parsec::makeError<builders::OpArg>("Reference expected", pos);
        }

        auto begin = pos + 1;
        auto next = begin;
        while (next < sv.size() && (std::isalnum(sv[next]) || extendedChars.find(sv[next]) != std::string::npos))
        {
            ++next;
        }

        if (next == begin)
        {
            return parsec::makeError<builders::OpArg>("Empty reference", pos);
        }

        return parsec::makeSuccess<builders::OpArg>(
            std::make_shared<builders::Reference>(std::string(sv.substr(begin, next - begin))), next);
    };
}

/**
 * @brief Parser for a single argument of a helper function that is a json value
 *
 * @return parsec::Parser<builders::OpArg>
 */
inline parsec::Parser<builders::OpArg> getHelperJsonArgParser()
{
    return [](auto sv, auto pos) -> parsec::Result<builders::OpArg>
    {
        if (pos >= sv.size())
        {
            return parsec::makeError<builders::OpArg>("Expected Json", pos);
        }

        // Try to parse as json value
        rapidjson::Reader reader;
        const auto ssInput = std::string(sv.substr(pos));
        rapidjson::StringStream ss(ssInput.c_str());
        rapidjson::Document doc;
        doc.ParseStream<rapidjson::kParseStopWhenDoneFlag>(ss);

        if (doc.HasParseError())
        {
            return parsec::makeError<builders::OpArg>("Error parsing json", pos);
        }

        auto next = pos + ss.Tell();
        const auto parsed = sv.substr(0, next);
        return parsec::makeSuccess<builders::OpArg>(std::make_shared<builders::Value>(json::Json(std::move(doc))),
                                                    next);
    };
}

/**
 * @brief Parser that returns a string value, used when the other argument parsers fail
 *
 * @return parsec::Parser<builders::OpArg>
 */
inline parsec::Parser<builders::OpArg> getHelperRawArgParser()
{
    std::string endChars = std::string {syntax::helper::ARG_ANCHOR, syntax::helper::ARG_END, ' '};
    std::string reservedChars = {syntax::helper::DEFAULT_ESCAPE, syntax::field::REF_ANCHOR};
    reservedChars += endChars;

    return [endChars, reservedChars](auto sv, auto pos) -> parsec::Result<builders::OpArg>
    {
        if (pos >= sv.size())
        {
            return parsec::makeError<builders::OpArg>("Expected argument", pos);
        }

        // Ensure that str does not start with a reserved character for the other parsers
        if (sv[pos] == syntax::helper::SINGLE_QUOTE || sv[pos] == syntax::field::REF_ANCHOR)
        {
            return parsec::makeError<builders::OpArg>("Invalid character", pos);
        }

        // Parse as string
        std::string rawStr;
        auto next = pos;
        while (next < sv.size())
        {
            if (endChars.find(sv[next]) != std::string::npos)
            {
                break;
            }

            if (sv[next] == syntax::helper::DEFAULT_ESCAPE)
            {
                if (next + 1 < sv.size() && reservedChars.find(sv[next + 1]) != std::string::npos)
                {
                    // Normal escape sequence
                    ++next;
                }
                else
                {
                    return parsec::makeError<builders::OpArg>("Invalid escape sequence", next + 1);
                }
            }

            rawStr += sv[next];
            ++next;
        }

        // Empty value
        if (rawStr.empty())
        {
            return parsec::makeSuccess<builders::OpArg>(std::make_shared<builders::Value>(), next);
        }

        json::Json value;
        value.setString(std::move(rawStr));

        return parsec::makeSuccess<builders::OpArg>(std::make_shared<builders::Value>(std::move(value)), next);
    };
}

/**
 * @brief Parser for a single argument of a helper function
 *
 * @return parsec::Parser<builders::OpArg>
 */
inline parsec::Parser<builders::OpArg> getHelperArgParser(parsec::Parser<std::string> sepParser = nullptr)
{
    parsec::Parser<builders::OpArg> argParser;
    if (sepParser)
    {
        argParser = (getHelperQuotedArgParser() << sepParser) | (getHelperRefArgParser() << sepParser)
                    | (getHelperJsonArgParser() << sepParser) | (getHelperRawArgParser() << sepParser);
    }
    else
    {
        argParser =
            getHelperQuotedArgParser() | getHelperRefArgParser() | getHelperJsonArgParser() | getHelperRawArgParser();
    }

    return argParser;
}

/**
 * @brief Parser for a helper function name
 *
 * @return parsec::Parser<std::string>
 */
inline parsec::Parser<std::string> getHelperNameParser()
{
    std::string helperExtended = syntax::helper::NAME_EXTENDED;

    return [helperExtended](auto sv, auto pos) -> parsec::Result<std::string>
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
}

/**
 * @brief Parser for a helper function
 *
 * @param eof if true will force end of string after the helper function
 * @return parsec::Parser<HelperToken>
 */
inline parsec::Parser<HelperToken> getHelperParser(bool eof = false)
{
    // helper_name([arg1, argN])
    auto helperNameParser = getHelperNameParser();
    parsec::Parser<std::string> parenthOpenParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (pos >= sv.size() || sv[pos] != syntax::helper::ARG_START)
        {
            return parsec::makeError<std::string>("Parenthesis open expected", pos);
        }

        // Skip whitespace
        auto next = pos + 1;
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        return parsec::makeSuccess<std::string>({}, next);
    };
    parsec::Parser<std::string> parenthCloseParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (pos >= sv.size())
        {
            return parsec::makeError<std::string>("Parenthesis close expected", pos);
        }

        // Skip whitespace
        auto next = pos;
        while (next < (sv.size() - 1) && std::isspace(sv[next]))
        {
            ++next;
        }

        if (sv[next] != syntax::helper::ARG_END)
        {
            return parsec::makeError<std::string>("Parenthesis close expected", next);
        }

        return parsec::makeSuccess<std::string>({}, ++next);
    };
    parsec::Parser<std::string> argSeparatorParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (pos >= sv.size())
        {
            return parsec::makeError<std::string>("Argument separator expected", pos);
        }

        // Skip whitespace before separator
        auto next = pos;
        while (next < (sv.size() - 1) && std::isspace(sv[next]))
        {
            ++next;
        }

        if (sv[next] != syntax::helper::ARG_ANCHOR)
        {
            return parsec::makeError<std::string>("Argument separator expected", next);
        }

        // Skip whitespace after separator
        ++next;
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        return parsec::makeSuccess<std::string>({}, next);
    };

    auto nameParser = helperNameParser << parenthOpenParser;
    auto middleSeparator = parsec::positiveLook(argSeparatorParser | parenthCloseParser);
    auto argParserMiddle = getHelperArgParser(middleSeparator) << argSeparatorParser;
    auto argParseEnd = getHelperArgParser(parenthCloseParser);
    auto argsParser = parsec::fmap<parsec::Values<OpArg>, std::tuple<parsec::Values<OpArg>, OpArg>>(
        [](auto&& tuple) -> parsec::Values<OpArg>
        {
            auto&& [args, arg] = tuple;
            args.emplace_back(std::move(arg));
            return args;
        },
        parsec::many(argParserMiddle) & argParseEnd);

    parsec::Parser<std::string> eofParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (pos < sv.size())
        {
            return parsec::makeError<std::string>("End of string expected", pos);
        }

        return parsec::makeSuccess<std::string>({}, pos);
    };

    auto helperParser = nameParser & argsParser;
    if (eof)
    {
        helperParser = helperParser << eofParser;
    }

    auto finalParser = parsec::fmap<HelperToken, std::tuple<std::string, parsec::Values<builders::OpArg>>>(
        [](auto&& tuple) -> HelperToken
        {
            HelperToken helperToken;
            helperToken.name = std::get<0>(tuple);

            // Transform values to arguments
            for (auto&& arg : std::get<1>(tuple))
            {
                helperToken.args.emplace_back(std::move(arg));
            }
            if (helperToken.args.size() == 1 && helperToken.args[0]->isValue()
                && std::static_pointer_cast<builders::Value>(helperToken.args[0])->value().isNull())
            {
                helperToken.args.clear();
            }

            return helperToken;
        },
        helperParser);

    return finalParser;
}

/**
 * @brief Check if the given string is a default helper, i.e. it does not start with helper name and parenthesis
 *
 * @param sv string to check
 * @return true if the string is a default helper
 */
inline bool isDefaultHelper(std::string_view sv)
{
    auto result = getHelperNameParser()(sv, 0);
    if (result.failure() || result.index() >= sv.size() || sv[result.index()] != syntax::helper::ARG_START)
    {
        return true;
    }

    return false;
}

/******************************************************************************/
/* Expression parsers */
/******************************************************************************/

// operators (==, !=, <, >, <=, >=)
enum class Operator
{
    EQUAL,
    NOT_EQUAL,
    GREATER_THAN,
    GREATER_THAN_OR_EQUAL,
    LESS_THAN,
    LESS_THAN_OR_EQUAL
};

constexpr auto operatorToString(Operator op)
{
    switch (op)
    {
        case Operator::EQUAL: return "==";
        case Operator::NOT_EQUAL: return "!=";
        case Operator::GREATER_THAN: return ">";
        case Operator::GREATER_THAN_OR_EQUAL: return ">=";
        case Operator::LESS_THAN: return "<";
        case Operator::LESS_THAN_OR_EQUAL: return "<=";
        default: return "Unknown operator";
    }
}

/**
 * @brief Represents a comparison operation token
 *
 */
struct OperationToken
{
    OpArg field; ///< Left side of the comparison (reference)
    Operator op; ///< Comparison operator
    OpArg value; ///< Right side of the comparison (reference or value)
};

/**
 * @brief Parser for comparison operators
 *
 * @return parsec::Parser<Operator>
 */
inline parsec::Parser<Operator> getOperatorParser()
{
    return [](auto sv, auto pos) -> parsec::Result<Operator>
    {
        // Ignore whitespace
        while (pos < sv.size() && std::isspace(sv[pos]))
        {
            ++pos;
        }

        if (pos >= sv.size())
        {
            return parsec::makeError<Operator>("Operator expected", pos);
        }

        Operator op;
        auto next = pos;

        if (sv[pos] == '=')
        {
            if (pos + 1 < sv.size() && sv[pos + 1] == '=')
            {
                op = Operator::EQUAL;
                next += 2;
            }
            else
            {
                return parsec::makeError<Operator>("Expected '='", pos + 1);
            }
        }
        else if (sv[pos] == '!')
        {
            if (pos + 1 < sv.size() && sv[pos + 1] == '=')
            {
                op = Operator::NOT_EQUAL;
                next += 2;
            }
            else
            {
                return parsec::makeError<Operator>("Expected '='", pos + 1);
            }
        }
        else if (sv[pos] == '>')
        {
            if (pos + 1 < sv.size() && sv[pos + 1] == '=')
            {
                op = Operator::GREATER_THAN_OR_EQUAL;
                next += 2;
            }
            else
            {
                op = Operator::GREATER_THAN;
                ++next;
            }
        }
        else if (sv[pos] == '<')
        {
            if (pos + 1 < sv.size() && sv[pos + 1] == '=')
            {
                op = Operator::LESS_THAN_OR_EQUAL;
                next += 2;
            }
            else
            {
                op = Operator::LESS_THAN;
                ++next;
            }
        }
        else
        {
            return parsec::makeError<Operator>("Invalid operator", pos);
        }

        // Ignore whitespace
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        return parsec::makeSuccess<Operator>(std::move(op), next);
    };
}

/**
 * @brief Parser for a comparison operation
 *
 * @return parsec::Parser<OperationToken>
 */
inline parsec::Parser<OperationToken> getOperationParser()
{
    auto refParser = getHelperRefArgParser();
    auto operatorParser = getOperatorParser();
    auto valueParser = getHelperArgParser();

    auto tokenParser = refParser & operatorParser & valueParser;
    auto finalParser = parsec::fmap<OperationToken, std::tuple<std::tuple<OpArg, Operator>, OpArg>>(
        [](auto&& tuple) -> OperationToken
        {
            OperationToken operationToken;
            operationToken.field = std::get<0>(std::get<0>(tuple));
            operationToken.op = std::get<1>(std::get<0>(tuple));
            operationToken.value = std::get<1>(tuple);

            return operationToken;
        },
        tokenParser);

    return finalParser;
}

/**
 * @brief Transform a comparison operation token to a helper token
 *
 * @return parsec::Parser<HelperToken>
 */
inline parsec::Parser<HelperToken> OpToHelperTokenMonadic(const OperationToken& opToken)
{
    return [opToken](auto sv, auto pos) -> parsec::Result<HelperToken>
    {
        if (opToken.field->isValue())
        {
            return parsec::makeError<HelperToken>("Left side of comparison operator must be a reference", pos);
        }

        HelperToken helperToken;
        helperToken.targetField = builders::Reference(*std::static_pointer_cast<builders::Reference>(opToken.field));

        if (opToken.op == Operator::EQUAL)
        {
            helperToken.name = "filter";
            helperToken.args.emplace_back(opToken.value);
            return parsec::makeSuccess<HelperToken>(std::move(helperToken), pos);
        }

        if (opToken.value->isReference())
        {
            return parsec::makeError<HelperToken>(
                fmt::format("Comparison operators only supports string or number values when using logic expressions, "
                            "but got reference '{}'",
                            std::static_pointer_cast<builders::Reference>(opToken.value)->dotPath()),
                pos);
        }

        const auto& value = std::static_pointer_cast<builders::Value>(opToken.value);
        if (value->value().isString())
        {
            helperToken.name = "string";
        }
        else if (value->value().isInt() || value->value().isInt64())
        {
            helperToken.name = "int";
        }
        else
        {
            return parsec::makeError<HelperToken>(
                fmt::format("Comparison operators only supports string or number values when using logic expressions, "
                            "but got '{}'",
                            value->value().str()),
                pos);
        }

        switch (opToken.op)
        {
            case Operator::GREATER_THAN: helperToken.name += "_greater"; break;
            case Operator::GREATER_THAN_OR_EQUAL: helperToken.name += "_greater_or_equal"; break;
            case Operator::LESS_THAN: helperToken.name += "_less"; break;
            case Operator::LESS_THAN_OR_EQUAL: helperToken.name += "_less_or_equal"; break;
            case Operator::NOT_EQUAL: helperToken.name += "_not_equal"; break;
        }

        helperToken.args.emplace_back(opToken.value);

        return parsec::makeSuccess<HelperToken>(std::move(helperToken), pos);
    };
}

/**
 * @brief Asserts that the given helper token has a target field as the first argument and returns a new helper token
 * with the target field
 *
 * @param helperToken
 * @return parsec::Parser<HelperToken>
 */
inline parsec::Parser<HelperToken> assertTargetMonadic(const HelperToken& helperToken)
{
    return [helperToken](auto sv, auto pos) -> parsec::Result<HelperToken>
    {
        if (helperToken.args.size() < 1)
        {
            return parsec::makeError<HelperToken>("At least one argument with target field expected", pos);
        }

        if (!helperToken.args[0]->isReference())
        {
            return parsec::makeError<HelperToken>("First argument must be a reference to target field", pos);
        }

        HelperToken next;
        next.name = helperToken.name;
        next.targetField = builders::Reference(*std::static_pointer_cast<builders::Reference>(helperToken.args[0]));
        next.args = std::vector<builders::OpArg>(helperToken.args.begin() + 1, helperToken.args.end());

        return parsec::makeSuccess<HelperToken>(std::move(next), pos);
    };
}

/**
 * @brief Parser for a helper function or a comparison operation
 *
 * @return parsec::Parser<HelperToken>
 */
inline parsec::Parser<HelperToken> getTermParser()
{
    parsec::M<HelperToken, HelperToken> targetM = [](const HelperToken& helperToken) -> parsec::Parser<HelperToken>
    {
        return assertTargetMonadic(helperToken);
    };
    auto helperParser = getHelperParser() >>= targetM;

    parsec::M<HelperToken, OperationToken> toOpM = [](const OperationToken& token) -> parsec::Parser<HelperToken>
    {
        return OpToHelperTokenMonadic(token);
    };
    auto opParser = getOperationParser() >>= toOpM;

    auto finalParser = helperParser | opParser;
    return finalParser;
}

} // namespace builder::builders::parsers

#endif // _BUILDER_HELPER_PARSER_HPP
