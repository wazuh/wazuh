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
#include <parsec/parsec.hpp>

#include "syntax.hpp"
#include "types.hpp"
#include "utils/stringUtils.hpp"

namespace builder::builders::detail
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
    builders::Reference targetField;
    std::vector<std::shared_ptr<builders::Argument>> args = {};

    friend std::ostream& operator<<(std::ostream& os, const HelperToken& helperToken)
    {
        std::string separator {};
        separator += syntax::helper::ARG_ANCHOR;

        // TODO implement
        // os << helperToken.name << "(" << base::utils::string::join(helperToken.args, separator, false) << ")";

        return os;
    }
};

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
inline HelperToken toBuilderInput(ExpressionToken& expressionToken)
{
    if (expressionToken.field.empty())
    {
        throw std::runtime_error("Expression field is empty");
    }

    bool isValueInteger = expressionToken.value.isInt() || expressionToken.value.isInt64();

    if (expressionToken.op == ExpressionOperator::EQUAL)
    {
        auto helperToken = HelperToken {};
        helperToken.name = "filter";
        helperToken.targetField = builders::Reference(expressionToken.field.substr(1));

        // If value is string, check if it is a reference
        if (expressionToken.value.isString()
            && expressionToken.value.getString().value()[0] == syntax::field::REF_ANCHOR)
        {

            helperToken.args.emplace_back(
                std::make_shared<builders::Reference>(expressionToken.value.getString().value().substr(1)));
        }
        else
        {
            helperToken.args.emplace_back(std::make_shared<builders::Value>(std::move(expressionToken.value)));
        }

        return helperToken;
    }

    if (expressionToken.op == ExpressionOperator::NOT_EQUAL && !expressionToken.value.isString() && !isValueInteger)
    {
        throw std::runtime_error("Not equal operator is not supported for non string or number values");
    }

    // Rest of operators only support string or number values
    if (!expressionToken.value.isString() && !isValueInteger)
    {
        throw std::runtime_error("Expression value is not string or number");
    }

    HelperToken helperToken {};

    if (isValueInteger)
    {
        helperToken.name = "int";
    }
    else
    {
        helperToken.name = "string";
    }
    helperToken.args.emplace_back(std::make_shared<builders::Value>(std::move(expressionToken.value)));

    switch (expressionToken.op)
    {
        case ExpressionOperator::GREATER_THAN: helperToken.name += "_greater"; break;
        case ExpressionOperator::GREATER_THAN_OR_EQUAL: helperToken.name += "_greater_or_equal"; break;
        case ExpressionOperator::LESS_THAN: helperToken.name += "_less"; break;
        case ExpressionOperator::LESS_THAN_OR_EQUAL: helperToken.name += "_less_or_equal"; break;
        case ExpressionOperator::NOT_EQUAL: helperToken.name += "_not_equal"; break;
        default: throw std::logic_error("Unknown expression operator");
    }

    helperToken.targetField = builders::Reference(expressionToken.field.substr(1));

    return helperToken;
}

using BuildToken = std::variant<HelperToken, ExpressionToken>;

inline parsec::Parser<std::string> getHelperStartParser() {
    std::string helperExtended = syntax::helper::NAME_EXTENDED;
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
        if (sv[pos] != syntax::helper::ARG_START)
        {
            return parsec::makeError<std::string>("Parenthesis open expected", pos);
        }
        // Skip whitespace
        auto next = pos + 1;
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        return parsec::makeSuccess(std::string(1, syntax::helper::ARG_START), next);
    };

    auto helperStartParser = helperNameParser >> parenthOpenParser;

    return helperStartParser;
}

/**
 * @brief Get a parser that parses a helper function
 * 
 * @return parsec::Parser<HelperToken>
 */
inline parsec::Parser<HelperToken> getHelperParser(bool eraseScapeChars = false) // TODO: Delete eraseScapeChars, true
{
    std::string helperExtended = syntax::helper::NAME_EXTENDED;
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
        if (sv[pos] != syntax::helper::ARG_START)
        {
            return parsec::makeError<std::string>("Parenthesis open expected", pos);
        }
        // Skip whitespace
        auto next = pos + 1;
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        return parsec::makeSuccess(std::string(1, syntax::helper::ARG_START), next);
    };

    auto helperStartParser = helperNameParser & parenthOpenParser;

    parsec::Parser<std::string> parenthCloseParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (sv[pos] != syntax::helper::ARG_END)
        {
            return parsec::makeError<std::string>("Parenthesis close expected", pos);
        }
        // Skip whitespace
        auto next = pos + 1;
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }

        return parsec::makeSuccess(std::string(1, syntax::helper::ARG_END), next);
    };

    parsec::Parser<std::string> behindParenthCloseParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (pos == 0 || sv[pos - 1] != syntax::helper::ARG_END)
        {
            return parsec::makeError<std::string>("Parenthesis close expected", pos);
        }

        return parsec::makeSuccess(std::string(1, syntax::helper::ARG_END), pos);
    };

    parsec::Parser<std::string> behindParenthOpenParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (pos == 0 || sv[pos - 1] != syntax::helper::ARG_START)
        {
            return parsec::makeError<std::string>("Parenthesis open expected", pos);
        }

        return parsec::makeSuccess(std::string(1, syntax::helper::ARG_START), pos);
    };

    parsec::Parser<std::string> simpleArgParser = [eraseScapeChars](auto sv, auto pos) -> parsec::Result<std::string>
    {
        auto next = pos;
        auto arg = std::string();

        if (next >= sv.size())
        {
            return parsec::makeError<std::string>("EOA", pos);
        }

        // Unescape \$ at the beginning of the parameter
        if (next + 1 < sv.size() && sv[next] == syntax::helper::DEFAULT_ESCAPE
            && sv[next + 1] == syntax::field::REF_ANCHOR)
        {
            arg += syntax::helper::DEFAULT_ESCAPE;
            ++next;
        }

        for (; next < sv.size(); ++next)
        {
            // Check for end of argument
            if (sv[next] == syntax::helper::ARG_ANCHOR || sv[next] == syntax::helper::ARG_END)
            {
                break;
            }
            // Check for escape sequence
            else if (sv[next] == syntax::helper::DEFAULT_ESCAPE)
            {
                if (next + 1 < sv.size())
                {
                    // Expecting escapeable character
                    if (sv[next + 1] == syntax::helper::ARG_ANCHOR || sv[next + 1] == syntax::helper::ARG_END
                        || sv[next + 1] == syntax::helper::DEFAULT_ESCAPE || std::isspace(sv[next + 1]))
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

    parsec::Parser<std::string> quotedArgParser = [eraseScapeChars](auto sv, auto pos) -> parsec::Result<std::string>
    {
        using namespace base::utils::string;
        auto next = pos;

        // Check if start with single quote
        if (next + 1 >= sv.size() || sv[next] != syntax::helper::SINGLE_QUOTE)
        {
            return parsec::makeError<std::string>("Single quote expected", pos);
        }
        next++;

        // Escape \$ at the beginning of the parameter
        bool escapedFirstReference = sv[next] == syntax::field::REF_ANCHOR;

        // Find end of string (unescaped single quote)
        bool valid = false;
        for (; next < sv.size(); ++next)
        {
            if (sv[next] == syntax::helper::SINGLE_QUOTE && sv[next - 1] != syntax::helper::DEFAULT_ESCAPE)
            {
                valid = true;
                break;
            }
        }

        if (!valid)
        {
            return parsec::makeError<std::string>("Invalid single quote string", pos);
        }

        // TODO: Add test for both cases
        std::string arg {};
        if (eraseScapeChars)
        {
            if (escapedFirstReference)
            {
                arg += syntax::helper::DEFAULT_ESCAPE;
            }
            // Discart start and end single quote
            auto quoted = sv.substr(pos + 1, next - pos - 1);
            // Unescape string
            arg += unescapeString(quoted, syntax::helper::DEFAULT_ESCAPE, syntax::helper::SINGLE_QUOTE, false);
        }
        else
        {
            arg = sv.substr(pos, next - pos + 1);
            if (escapedFirstReference)
            {
                arg.insert(1, 1, syntax::helper::DEFAULT_ESCAPE);
            }
        }
        // "string_equal($processname,   '')"
        next++;
        while (next < sv.size() && std::isspace(sv[next]))
        {
            ++next;
        }
        return parsec::makeSuccess(std::move(arg), next);
    };

    parsec::Parser<std::string> endArgParser = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        parsec::Result<std::string> res;
        auto next = pos;
        if (sv[next] == syntax::helper::ARG_ANCHOR)
        {
            // Optional whitespaces (TODO check case ( a    , c    ))
            ++next;
            while (next < sv.size() && std::isspace(sv[next]))
            {
                ++next;
            }

            res = parsec::makeSuccess(std::string(sv.substr(pos, next - pos)), next);
        }
        else if (sv[next] == syntax::helper::ARG_END)
        {
            res = parsec::makeSuccess(std::string(sv.substr(pos, 1)), pos + 1);
        }
        else
        {
            res = parsec::makeError<std::string>("Argument separator or parenthesis close expected", pos);
        }

        return res;
    };

    // Empty arguments parser, parenthesis that closes, and behind a parenthesis that opens
    auto helperNoArgsParserRaw = parsec::positiveLook(behindParenthOpenParser) >> parenthCloseParser;
    // returns a empty list of arguments
    auto helperNoArgsParser = parsec::fmap<parsec::Values<std::string>, std::string>(
        [](auto&& tuple) -> parsec::Values<std::string> { return {}; }, helperNoArgsParserRaw);

    // Some arguments parser, can be a quoted string or scaped string
    auto argParser = quotedArgParser | simpleArgParser;
    auto helperSomeArgsParser =
        parsec::many1(parsec::negativeLook(behindParenthCloseParser) >> argParser << endArgParser);

    // A helper function can have no arguments or some arguments
    auto helperArgsParser = helperNoArgsParser | helperSomeArgsParser;

    auto helperParserRaw =
        (helperNameParser << parenthOpenParser) & (helperArgsParser << parsec::positiveLook(behindParenthCloseParser));
    auto helperParser = parsec::fmap<HelperToken, std::tuple<std::string, parsec::Values<std::string>>>(
        [](auto&& tuple) -> HelperToken
        {
            HelperToken helperToken;
            helperToken.name = std::get<0>(tuple);

            // Transform values to arguments
            for (auto&& arg : std::get<1>(tuple))
            {
                // If not json value, the it could be a reference or defaults to string
                std::shared_ptr<builders::Argument> argument;

                try
                {
                    argument = std::make_shared<builders::Value>(json::Json(arg.c_str()));
                }
                catch (const std::exception&)
                {
                    // Check if it is a reference
                    if (arg[0] == syntax::field::REF_ANCHOR)
                    {
                        argument = std::make_shared<builders::Reference>(arg.substr(1));
                    }
                    else
                    {
                        auto strValue = json::Json();
                        strValue.setString(arg);
                        argument = std::make_shared<builders::Value>(std::move(strValue));
                    }
                }

                helperToken.args.emplace_back(std::move(argument));
            }

            return helperToken;
        },
        helperParserRaw);

    // Can be a value or reference if it does not start with a helper name
    parsec::Parser<std::string> refParserRaw = [](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (sv[pos] != syntax::field::REF_ANCHOR)
        {
            return parsec::makeError<std::string>("Reference expected", pos);
        }

        // Return everything after the reference anchor
        return parsec::makeSuccess(std::string(sv.substr(pos)), sv.size());
    };
    auto refParser = parsec::fmap<HelperToken, std::string>(
        [](auto&& str) -> HelperToken
        {
            HelperToken helperToken;
            helperToken.name = "";
            helperToken.args.emplace_back(std::make_shared<builders::Reference>(str.substr(1)));
            return helperToken;
        },
        refParserRaw);

    parsec::Parser<HelperToken> valueParser = [](auto sv, auto pos) -> parsec::Result<HelperToken>
    {
        // Try to parse as json, otherwise it is a string
        HelperToken helperToken;
        helperToken.name = "";
        try
        {
            helperToken.args.emplace_back(std::make_shared<builders::Value>(json::Json(sv.substr(pos).data())));
        }
        catch (const std::exception&)
        {
            // If empty error
            if (sv.size() <= pos)
            {
                return parsec::makeError<HelperToken>("Empty value", pos);
            }

            auto strValue = json::Json();
            // Check for escape helper syntax 'helperName()'
            if (sv[pos] == '\'')
            {
                if (sv[sv.size() - 1] != '\'')
                {
                    return parsec::makeError<HelperToken>("Missing end quote", pos);
                }

                strValue.setString(sv.substr(pos + 1, sv.size() - pos - 2));
            }
            // Check for escaped quote
            else if (sv[pos] == syntax::helper::DEFAULT_ESCAPE && sv[pos + 1] == '\'')
            {
                strValue.setString(sv.substr(pos + 1, sv.size() - pos - 1));
            }
            else
            {
                strValue.setString(sv.substr(pos));
            }

            helperToken.args.emplace_back(std::make_shared<builders::Value>(std::move(strValue)));
        }

        return parsec::makeSuccess(std::move(helperToken), sv.size());
    };

    // auto finalParser = helperParser | (parsec::negativeLook(helperStartParser) >> (refParser | valueParser));
    // return finalParser;
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
        [fieldExtended = std::string(syntax::field::NAME_EXTENDED) + syntax::field::SEPARATOR
                         + syntax::helper::DEFAULT_ESCAPE](auto sv, auto pos) -> parsec::Result<std::string>
    {
        if (sv[pos] != syntax::field::REF_ANCHOR)
        {
            return parsec::makeError<std::string>("Reference expected", pos);
        }

        auto next = pos + 1;

        while (next < sv.size() && (std::isalnum(sv[next]) || fieldExtended.find(sv[next]) != std::string::npos))
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
        // The word ends with a space, parenthesis or end of string
        while (next < sv.size() && !std::isspace(sv[next]) && sv[next] != syntax::helper::ARG_END
               && sv[next] != syntax::helper::ARG_START)
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

    parsec::Parser<json::Json> singleQuotesParser = [](auto sv, auto pos) -> parsec::Result<json::Json>
    {
        using namespace base::utils::string;
        auto next = pos;
        // Check if start with single quote
        if (next + 1 >= sv.size() || sv[next] != syntax::helper::SINGLE_QUOTE)
        {
            return parsec::makeError<json::Json>("Single quote expected", pos);
        }
        next++;

        // Find end of string (unescaped single quote)
        bool valid = false;
        for (; next < sv.size(); ++next)
        {
            if (sv[next] == syntax::helper::SINGLE_QUOTE && sv[next - 1] != syntax::helper::DEFAULT_ESCAPE)
            {
                valid = true;
                break;
            }
        }

        if (!valid)
        {
            return parsec::makeError<json::Json>("Invalid single quote string", pos);
        }

        const auto quoted = sv.substr(pos + 1, next - pos - 1);
        const auto str = unescapeString(quoted, syntax::helper::DEFAULT_ESCAPE, syntax::helper::SINGLE_QUOTE, false);

        json::Json value;
        value.setString(str);

        return parsec::makeSuccess(std::move(value), next + 1);
    };

    auto valueParser = valueRefParser | jsonParser | singleQuotesParser | wordParser;

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
// TODO remove ExpressionToken, as it can directly be converted to HelperToken
inline parsec::Parser<BuildToken> getTermParser()
{
    auto helperParser = getHelperParser(true);
    auto expressionParser = getExpressionParser();

    parsec::M<HelperToken, HelperToken> f = [](const HelperToken& token) -> parsec::Parser<HelperToken>
    {
        parsec::Parser<HelperToken> parser = [token](auto sv, auto pos) -> parsec::Result<HelperToken>
        {
            if (token.name.empty())
            {
                return parsec::makeError<HelperToken>("Helper function syntax error", pos);
            }

            if (token.args.size() < 1 || token.args[0]->isValue())
            {
                return parsec::makeError<HelperToken>(
                    "Helper function requires at least one argument referencing target field", pos);
            }

            HelperToken newToken;
            newToken.name = token.name;
            newToken.targetField = *std::static_pointer_cast<builders::Reference>(token.args[0]);
            newToken.args = std::vector<std::shared_ptr<builders::Argument>>(token.args.begin() + 1, token.args.end());

            return parsec::makeSuccess<HelperToken>(std::move(newToken), pos);
        };

        return parser;
    };
    parsec::Parser<HelperToken> finalHelperParser = helperParser >>= f;

    parsec::Parser<BuildToken> helperParserToken = parsec::fmap<BuildToken, HelperToken>(
        [](auto&& helperToken) -> BuildToken { return std::move(helperToken); }, finalHelperParser);
    parsec::Parser<BuildToken> expressionParserToken = parsec::fmap<BuildToken, ExpressionToken>(
        [](auto&& expressionToken) -> BuildToken { return std::move(expressionToken); }, expressionParser);

    parsec::Parser<BuildToken> parser = expressionParserToken | helperParserToken;

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
} // namespace builder::builders::detail

#endif // _BUILDER_HELPER_PARSER_HPP
