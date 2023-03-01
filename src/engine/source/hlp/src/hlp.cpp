#include <stdexcept>
#include <cstdio>
#include <string>
#include <unordered_map>
#include <vector>

#include "hlpDetails.hpp"
#include "logParser.hpp"
#include "specificParsers.hpp"

#include <hlp/hlp.hpp>
#include <logging/logging.hpp>
#include <profile/profile.hpp>
#include <rapidjson/document.h>

namespace hlp
{
using ParserList = std::vector<Parser>;

static bool sInitialized = false;
static std::unordered_map<std::string, ParserType> kECSParserMapper;

void configureParserMappings(const std::string& config)
{
    static const std::unordered_map<std::string_view, ParserType> kSchema2ParserType {
        {"keyword", ParserType::Any},
        {"any", ParserType::ToEnd},
        {"ip", ParserType::IP},
        {"timestamp", ParserType::Ts},
        {"date", ParserType::Ts},
        {"url", ParserType::URL},
        {"json", ParserType::JSON},
        {"kv_map", ParserType::KVMap},
        {"domain", ParserType::Domain},
        {"filepath", ParserType::FilePath},
        {"useragent", ParserType::UserAgent},
        {"float", ParserType::Number},
        {"long", ParserType::Number},
        {"scaled_float", ParserType::Number},
        {"short", ParserType::Number},
        {"quoted", ParserType::QuotedString},
        {"boolean", ParserType::Boolean},
        {"xml", ParserType::Xml},
        {"text", ParserType::Any},
        {"ignore", ParserType::Ignore}};

    if (config.empty())
    {
        WAZUH_LOG_ERROR("Engine HLP: Schema configuration is empty.");
        return;
    }

    rapidjson::Document doc;
    doc.Parse(config.c_str());

    if (doc.HasParseError())
    {
        WAZUH_LOG_ERROR("Engine HLP: \"{}\" method: An error occurred while parsing "
                        "configuration at offset {} in the configuration.",
                        __func__,
                        doc.GetErrorOffset());
        return;
    }

    for (auto it = doc.MemberBegin(); it != doc.MemberEnd(); it++)
    {
        auto pt = kSchema2ParserType.find(it->value.GetString());
        if (pt != kSchema2ParserType.end())
        {
            kECSParserMapper[it->name.GetString()] = pt->second;
        }
        else
        {
            WAZUH_LOG_DEBUG("Engine HLP: \"{}\" method: Invalid parser type \"{}\" for "
                            "field \"{}\" in the configuration.",
                            __func__,
                            it->value.GetString(),
                            it->name.GetString());
        }
    }
}

static const std::unordered_map<std::string_view, ParserType> kTempTypeMapper {
    {"json", ParserType::JSON},
    {"kv_map", ParserType::KVMap},
    {"timestamp", ParserType::Ts},
    {"domain", ParserType::Domain},
    {"filepath", ParserType::FilePath},
    {"useragent", ParserType::UserAgent},
    {"url", ParserType::URL},
    {"quoted", ParserType::QuotedString},
    {"ip", ParserType::IP},
    {"number", ParserType::Number},
    {"toend", ParserType::ToEnd},
    {"ignore", ParserType::Ignore},
    {"xml", ParserType::Xml},
    {"csv", ParserType::CSV},
    // TODO add missing parsers
};

/**
 * @brief Creates an options vector from a slash-separated string.
 *
 * @param str slash-separated string with all the options
 * @return std::vector with all the options in the string expression.
 * @note This function requires that the original string live for the duration
 *       that you need each piece as the vector refers to the original string
 */
static std::vector<std::string_view> splitSlashSeparatedField(std::string_view str)
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

static void setParserOptions(Parser& parser, std::vector<std::string_view> const& args)
{
    auto config = kParsersConfig[static_cast<int>(parser.type)];
    if (config)
    {
        config(parser, args);
    }
}

Parser createParserFromExpresion(Expression const& exp)
{
    // We could be parsing:
    //      '<TMP_FIELD_PREFIX>'
    //      '<TMP_FIELD_PREFIXname>'
    //      '<TMP_FIELD_PREFIXname/type>'
    //      '<TMP_FIELD_PREFIXname/type/type2>'
    auto args = splitSlashSeparatedField(exp.text);
    Parser parser;
    parser.expType = exp.type;
    parser.endToken = exp.endToken;
    parser.name = args[0];
    args.erase(args.begin());
    parser.type = ParserType::Any;
    if (parser.name[0] == TMP_FIELD_PREFIX)
    {
        // TODO: temporary fields should be trimmed on the final event
        //  We have a temp capture with the format <_temp/type/typeN>
        //  we need to take the first parameter after the name and set the
        //  type from it
        if (!args.empty())
        {
            auto it = kTempTypeMapper.find(args[0]);
            if (kTempTypeMapper.end() != it)
            {
                parser.type = it->second;
            }
            // erase the type from the list so we are
            // consistent with the non temp case
            args.erase(args.begin());
        }
    }
    else
    {
        auto it = kECSParserMapper.find(parser.name);
        if (kECSParserMapper.end() != it)
        {
            parser.type = it->second;
        }
        else
        {
            throw std::runtime_error(fmt::format(
                "Field \"{}\" in logparse expression is not a valid ECS field",
                parser.name));
        }
    }

    setParserOptions(parser, args);

    return parser;
}

std::vector<Parser> getParserList(ExpressionList const& expressions)
{
    WAZUH_TRACE_FUNCTION;
    std::vector<Parser> parsers;

    for (auto const& expresion : expressions)
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
                throw std::runtime_error("Invalid type of parsed expression");
            }
        }
    }

    return parsers;
}

static ExecuteResult executeParserList(std::string_view const& event,
                                       ParserList const& parsers,
                                       ParseResult& result)
{
    WAZUH_TRACE_FUNCTION_S(5);
    const char* eventIt = event.data();

    // TODO This implementation is super simple for the POC
    // but we will want to re-do it or revise it to implement
    // better parser combinations
    bool isOk = true;
    std::string trace;
    for (auto const& parser : parsers)
    {
        WAZUH_TRACE_SCOPE("parserLoop");
        const char* prevIt = eventIt;
        auto parseFunc = kAvailableParsers[static_cast<int>(parser.type)];
        if (parseFunc != nullptr)
        {
            isOk = parseFunc(&eventIt, parser, result);
        }
        else
        {
            // ASSERT here we are missing an implementation
            // TODO: review this
            return ExecuteResult {false,
                                  trace
                                      + fmt::format("Parser[\"{}\"] failure: Missing "
                                                    "implementation for parser \"{}\"",
                                                    parser.name,
                                                    parser.name)};
        }

        if (!isOk)
        {
            if (parser.expType == ExpressionType::OptionalCapture
                || parser.expType == ExpressionType::OrCapture)
            {
                // We need to test the second part of the 'OR' capture
                eventIt = prevIt;
                isOk = true; // Not strictly necessary
            }
            else
            {
                // TODO report error <field>?<other>
                // TODO: review this
                return ExecuteResult {
                    false, trace + fmt::format("Parser[\"{}\"] failure", parser.name)};
            }
        }
        else
        {
            trace += fmt::format("Parser[\"{}\"] success\n", parser.name);
        }
    }

    return ExecuteResult {isOk, trace};
}

ParserFn getParserOp(std::string_view const& logpar)
{
    WAZUH_TRACE_FUNCTION;
    if (logpar.empty())
    {
        throw std::invalid_argument("Empty Logpar expression");
    }

    ExpressionList expressions = parseLogExpr(logpar.data());
    if (expressions.empty())
    {
        throw std::runtime_error(
            fmt::format("Empty expression output obtained from parsing \"{}\"", logpar));
    }

    auto parserList = getParserList(expressions);
    if (parserList.empty())
    {
        throw std::runtime_error(fmt::format(
            "Could not convert expressions to parser List from \"{}\"", logpar));
    }

    ParserFn parseFn = [parserList = std::move(parserList)](std::string_view const& event,
                                                            ParseResult& result)
    {
        return executeParserList(event, parserList, result);
    };

    return parseFn;
}
} // namespace hlp
