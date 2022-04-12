#include <stdexcept>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "hlpDetails.hpp"
#include "logQLParser.hpp"
#include "specificParsers.hpp"
#include <hlp/hlp.hpp>
#include <profile/profile.hpp>

using ParserList = std::vector<Parser>;

static const std::unordered_map<std::string_view, ParserType> kECSParserMapper {
    {"source.ip", ParserType::IP},
    {"server.ip", ParserType::IP},
    {"source.nat.ip", ParserType::IP},
    {"timestamp", ParserType::Ts},
    {"threat.indicator.first_seen", ParserType::Ts},
    {"file.accessed", ParserType::Ts},
    {"file.created", ParserType::Ts},
    {"url", ParserType::URL},
    {"http.request.method", ParserType::Any},
    {"client", ParserType::Domain},
    {"userAgent", ParserType::UserAgent},
    {"any", ParserType::ExpicitAny},
    {"client.registered_domain", ParserType::KeyWord},
    {"file.size", ParserType::Number}, //long
    {"vulnerability.score.temporal", ParserType::Number}, //float
};

static const std::unordered_map<std::string_view, ParserType> kTempTypeMapper {
    {"JSON", ParserType::JSON},
    {"MAP", ParserType::Map},
    {"timestamp", ParserType::Ts},
    {"domain", ParserType::Domain},
    {"FilePath", ParserType::FilePath},
    {"userAgent", ParserType::UserAgent},
    {"url", ParserType::URL},
    {"quoted_string", ParserType::QuotedString},
};

/**
 * @brief Creates an options vector from a slash-separated string.
 *
 * @param str slash-separated string with all the options
 * @return std::vector with all the options in the string expression.
 * @note This function requires that the original string live for the duration
 *       that you need each piece as the vector refers to the original string
 */
static std::vector<std::string_view>
splitSlashSeparatedField(std::string_view str)
{
    std::vector<std::string_view> ret;
    while (true)
    {
        auto pos = str.find('/');
        if (pos == str.npos)
        {
            break;
        }
        ret.emplace_back(str.substr(0, pos));
        str = str.substr(pos + 1);
    }

    if (!str.empty())
    {
        ret.emplace_back(str);
    }

    return ret;
}

static void setParserOptions(Parser &parser,
                             std::vector<std::string_view> const &args)
{
    auto config = kParsersConfig[static_cast<int>(parser.type)];
    if (config)
    {
        config(parser, args);
    }
}

Parser createParserFromExpresion(Expression const &exp)
{
    // We could be parsing:
    //      '<_>'
    //      '<_name>'
    //      '<_name/type>'
    //      '<_name/type/type2>'
    auto args = splitSlashSeparatedField(exp.text);
    Parser parser;
    parser.expType = exp.type;
    parser.endToken = exp.endToken;
    parser.name = args[0];
    args.erase(args.begin());
    parser.type = ParserType::Any;
    if (parser.name[0] == '_')
    {
        if (parser.name.size() != 1)
        {
            // We have a temp capture with the format <_temp/type/typeN>
            // we need to take the first parameter after the name and set the
            // type from it
            if (!args.empty())
            {
                auto it = kTempTypeMapper.find(args[0]);
                if (it != kTempTypeMapper.end())
                {
                    parser.type = it->second;
                }
                // erase the type from the list so we are
                // consistent with the non temp case
                args.erase(args.begin());
            }
        }
    }
    else
    {
        auto it = kECSParserMapper.find(parser.name);
        if (it != kECSParserMapper.end())
        {
            parser.type = it->second;
        }
    }

    setParserOptions(parser, args);

    return parser;
}

std::vector<Parser> getParserList(ExpressionList const &expressions)
{
    WAZUH_TRACE_FUNCTION;
    std::vector<Parser> parsers;

    for (auto const &expresion : expressions)
    {
        switch (expresion.type)
        {
            case ExpressionType::Capture:
            case ExpressionType::OptionalCapture:
            case ExpressionType::OrCapture:
            {
                parsers.push_back(createParserFromExpresion(expresion));
                break;
            }
            case ExpressionType::Literal:
            {
                Parser p;
                p.name = expresion.text;
                p.type = ParserType::Literal;
                p.expType = ExpressionType::Literal;
                p.endToken = expresion.endToken;
                parsers.push_back(p);
                break;
            }
            default:
            {
                throw std::runtime_error(
                    "[HLP]Invalid expression parsed from LogQL expression");
            }
        }
    }

    return parsers;
}

static bool executeParserList(std::string_view const &event,
                              ParserList const &parsers,
                              ParseResult &result)
{
    WAZUH_TRACE_FUNCTION_S(5);
    const char *eventIt = event.data();

    // TODO This implementation is super simple for the POC
    // but we will want to re-do it or revise it to implement
    // better parser combinations
    bool isOk = true;
    for (auto const &parser : parsers)
    {
        WAZUH_TRACE_SCOPE("parserLoop");
        const char *prevIt = eventIt;
        auto parseFunc = kAvailableParsers[static_cast<int>(parser.type)];
        if (parseFunc != nullptr)
        {
            WAZUH_TRACE_SCOPE("parserFunc");
            isOk = parseFunc(&eventIt, parser, result);
        }
        else
        {
            // ASSERT here we are missing an implementation
            return false;
        }

        if (!isOk)
        {
            if (parser.expType == ExpressionType::OptionalCapture ||
                parser.expType == ExpressionType::OrCapture)
            {
                // We need to test the second part of the 'OR' capture
                eventIt = prevIt;
                isOk = true; // Not strictly necessary
            }
            else
            {
                // TODO report error
                return false;
            }
        }
    }

    return true;
}

ParserFn getParserOp(std::string_view const &logQl)
{
    WAZUH_TRACE_FUNCTION;
    if (logQl.empty())
    {
        throw std::invalid_argument("[HLP]Empty LogQL expression");
    }

    ExpressionList expressions = parseLogQlExpr(logQl.data());
    if (expressions.empty())
    {
        throw std::runtime_error(
            "[HLP]Empty expression output obtained from LogQL parsing");
    }

    auto parserList = getParserList(expressions);
    if (parserList.empty())
    {
        throw std::runtime_error(
            "[HLP]Could not convert expressions to parser List");
    }

    ParserFn parseFn = [parserList = std::move(parserList)](
                           std::string_view const &event, ParseResult &result)
    {
        return executeParserList(event, parserList, result);
    };

    return parseFn;
}
