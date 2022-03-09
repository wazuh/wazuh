#include <algorithm>
#include <functional>
#include <stdio.h>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "LogQLParser.hpp"
#include "SpecificParsers.hpp"
#include "hlpDetails.hpp"

#include <hlp/hlp.hpp>

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
};

static const std::unordered_map<std::string_view, ParserType> kTempTypeMapper {
    {"JSON", ParserType::JSON},
    {"MAP", ParserType::Map},
    {"timestamp", ParserType::Ts},
    {"domain", ParserType::Domain},
    {"FilePath", ParserType::FilePath},
    {"userAgent", ParserType::UserAgent},
};

// NOTE: This function requires that the original string live for the duration
// that you need each piece as the vector refers to the original string
static std::vector<std::string_view>
splitSlashSeparatedField(std::string_view str)
{
    std::vector<std::string_view> ret;
    while(true)
    {
        auto pos = str.find('/');
        if(pos == str.npos)
        {
            break;
        }
        ret.emplace_back(str.substr(0, pos));
        str = str.substr(pos + 1);
    }

    if(!str.empty())
    {
        ret.emplace_back(str);
    }

    return ret;
}

static bool setParserOptions(Parser &parser,
                             std::vector<std::string_view> const &args)
{
    auto config = kParsersConfig[static_cast<int>(parser.type)];
    if(config)
    {
        return config(parser, args);
    }

    return false;
}

Parser createParserFromExpresion(Expresion const& exp)
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
    if(parser.name[0] == '_')
    {
        if(parser.name.size() != 1)
        {
            // We have a temp capture with the format <_temp/type/typeN>
            // we need to take the first parameter after the name and set the
            // type from it
            if(!args.empty())
            {
                auto it = kTempTypeMapper.find(args[0]);
                if(it != kTempTypeMapper.end())
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
        if(it != kECSParserMapper.end())
        {
            parser.type = it->second;
        }
    }

    setParserOptions(parser, args);

    return parser;
}

std::vector<Parser> getParserList(ExpresionList const &expresions)
{
    std::vector<Parser> parsers;

    for(auto const &expresion : expresions)
    {
        switch(expresion.type)
        {
            case ExpresionType::Capture:
            case ExpresionType::OptionalCapture:
            case ExpresionType::OrCapture:
            {
                parsers.push_back(createParserFromExpresion(expresion));
                break;
            }
            case ExpresionType::Literal:
            {
                Parser p;
                p.name = expresion.text;
                p.type = ParserType::Literal;
                p.expType = ExpresionType::Literal;
                p.endToken = expresion.endToken;
                parsers.push_back(p);
                break;
            }
            default:
            {
                // TODO report error
                break;
            }
        }
    }

    return parsers;
}

static bool executeParserList(std::string const &event,
                              ParserList const &parsers,
                              ParseResult &result)
{
    const char *eventIt = event.c_str();

    // TODO This implementation is super simple for the POC
    // but we will want to re-do it or revise it to implement
    // better parser combinations
    bool isOk = false;
    for(auto const &parser : parsers)
    {
        const char *prevIt = eventIt;
        auto parseFunc = kAvailableParsers[static_cast<int>(parser.type)];
        if(parseFunc != nullptr)
        {
            isOk = parseFunc(&eventIt, parser, result);
        }
        else
        {
            isOk = false;
            fprintf(stderr,
                    "Missing implementation for parser type: [%i]\n",
                    parser.type);
            break;
        }

        if(!isOk)
        {
            if(parser.expType == ExpresionType::OptionalCapture ||
               parser.expType == ExpresionType::OrCapture)
            {
                // We need to test the second part of the 'OR' capture
                eventIt = prevIt;
                isOk = false;
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

ParserFn getParserOp(std::string const &logQl)
{
    if(logQl.empty())
    {
        // TODO report error - empty logQl expresion string
        return {};
    }

    ExpresionList expresions = parseLogQlExpr(logQl);
    if(expresions.empty())
    {
        // TODO some error occured while parsing the logQl expr
        return {};
    }

    auto parserList = getParserList(expresions);
    if(parserList.empty())
    {
        // TODO some error occured while parsing the logQl expr
        return {};
    }

    ParserFn parseFn = [expr = logQl, parserList = std::move(parserList)](
                           std::string const &event, ParseResult &result)
    {
        return executeParserList(event, parserList, result);
    };

    return parseFn;
}
