#include "builders/optransform/hlp.hpp"

#include <optional>

#include <fmt/format.h>

#include <base/logging.hpp>
#include <hlp/hlp.hpp>

using builder::syntax::field::REF_ANCHOR;

namespace
{
using namespace builder::builders;

enum class HLPParserType
{
    ALPHANUMERIC,
    BOOL,
    BYTE,
    LONG,
    FLOAT,
    DOUBLE,
    SCALED_FLOAT,
    TEXT,
    QUOTED,
    BETWEEN,
    BINARY,
    DATE,
    IP,
    URI,
    USERAGENT,
    FQDN,
    FILE,
    JSON,
    XML,
    DSV,
    CSV,
    KV,
};

auto parserGetter(HLPParserType parserType)
{

    switch (parserType)
    {
        case HLPParserType::ALPHANUMERIC: return hlp::parsers::getAlphanumericParser;
        case HLPParserType::BOOL: return hlp::parsers::getBoolParser;
        case HLPParserType::BYTE: return hlp::parsers::getByteParser;
        case HLPParserType::LONG: return hlp::parsers::getLongParser;
        case HLPParserType::FLOAT: return hlp::parsers::getFloatParser;
        case HLPParserType::DOUBLE: return hlp::parsers::getDoubleParser;
        case HLPParserType::SCALED_FLOAT: return hlp::parsers::getScaledFloatParser;
        case HLPParserType::QUOTED: return hlp::parsers::getQuotedParser;
        case HLPParserType::BETWEEN: return hlp::parsers::getBetweenParser;
        case HLPParserType::BINARY: return hlp::parsers::getBinaryParser;
        case HLPParserType::DATE: return hlp::parsers::getDateParser;
        case HLPParserType::IP: return hlp::parsers::getIPParser;
        case HLPParserType::URI: return hlp::parsers::getUriParser;
        case HLPParserType::USERAGENT: return hlp::parsers::getUAParser;
        case HLPParserType::FQDN: return hlp::parsers::getFQDNParser;
        case HLPParserType::FILE: return hlp::parsers::getFilePathParser;
        case HLPParserType::JSON: return hlp::parsers::getJSONParser;
        case HLPParserType::XML: return hlp::parsers::getXMLParser;
        case HLPParserType::DSV: return hlp::parsers::getDSVParser;
        case HLPParserType::CSV: return hlp::parsers::getCSVParser;
        case HLPParserType::KV: return hlp::parsers::getKVParser;
        default: throw std::logic_error("Invalid HLP parser type");
    }
}

} // namespace

namespace builder::builders::optransform
{

namespace detail
{
TransformOp specificHLPBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx,
                               const std::function<hlp::parser::Parser(const hlp::Params& params)>& parserBuilder)
{
    // Check if the number of parameters is correct
    utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);
    utils::assertRef(opArgs, 0);

    // Get parser builder parameters
    std::vector<OpArg> newParameters(opArgs.begin() + 1, opArgs.end());
    hlp::Options hlpOptionsList {};
    hlpOptionsList.reserve(newParameters.size());

    // Check that the rest of parameter are values and get the value
    utils::assertValue(newParameters);
    for (const auto& param : newParameters)
    {
        auto value = std::static_pointer_cast<Value>(param);
        if (!value->value().isString())
        {
            throw std::runtime_error(fmt::format("Got non 'string' parameter '{}'", value->value().str()));
        }

        hlpOptionsList.emplace_back(value->value().getString().value());
    }

    hlp::parser::Parser parser;
    hlp::Params params {
        .name = "parser", .targetField = targetField.jsonPath(), .stop = {""}, .options = hlpOptionsList};

    parser = parserBuilder(params);

    // Parser must consume all input, add EOF parser
    parser = hlp::parser::combinator::all({parser, hlp::parsers::getEofParser({.name = "EOF"})});

    // Get the source
    const auto& source = *std::static_pointer_cast<Reference>(opArgs[0]);

    if (buildCtx->validator().hasField(source.dotPath()))
    {
        auto jType = buildCtx->validator().getJsonType(source.dotPath());
        if (jType != json::Json::Type::String)
        {
            throw std::runtime_error(
                fmt::format("Expected source reference to be of type 'string' but got '{}' which is of type '{}'",
                            source.dotPath(),
                            json::Json::typeToStr(jType)));
        }
    }

    const auto traceName = buildCtx->context().opName;
    const auto successTrace = fmt::format("{} -> Success", traceName);
    const auto failureTrace = fmt::format("{} -> ", traceName);
    const auto failureTrace1 =
        fmt::format("{} -> Reference '{}' is not a string or it doesn't exist", traceName, source.dotPath());
    const auto failureTrace3 = fmt::format("{} -> There is still text to analyze after parsing", traceName);

    // Return Op
    return [=, source = source.jsonPath(), runState = buildCtx->runState(), parser = std::move(parser)](
               base::Event event) -> TransformResult
    {
        // Check if source is a reference
        const auto sourceValue = event->getString(source);
        if (!sourceValue)
        {
            RETURN_FAILURE(runState, event, failureTrace1);
        }

        // Parse source
        auto error = hlp::parser::run(parser, sourceValue.value(), *event);
        if (error)
        {
            RETURN_FAILURE(runState, event, failureTrace + error.value().message);
        }

        RETURN_SUCCESS(runState, event, successTrace);
    };
}

} // namespace detail

//*************************************************
//*         HLP Specific parser Helpers           *
//*************************************************
// +parse_bool/[$ref|value]
TransformOp boolParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::BOOL));
}

// +parse_byte/[$ref|value]
TransformOp byteParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::BYTE));
}

// +parse_long/[$ref|value]
TransformOp longParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::LONG));
}

// +parse_float/[$ref|value]
TransformOp floatParseBuilder(const Reference& targetField,
                              const std::vector<OpArg>& opArgs,
                              const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::FLOAT));
}

// +parse_double/[$ref|value]
TransformOp doubleParseBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::DOUBLE));
}

// +parse_binary/[$ref|value]
TransformOp binaryParseBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::BINARY));
}

// +parse_date/[$ref|value]
TransformOp dateParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::DATE));
}

// +parse_ip/[$ref|value]
TransformOp ipParseBuilder(const Reference& targetField,
                           const std::vector<OpArg>& opArgs,
                           const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::IP));
}

// +parse_uri/[$ref|value]
TransformOp uriParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::URI));
}

// +parse_useragent/[$ref|value]
TransformOp userAgentParseBuilder(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::USERAGENT));
}

// +parse_fqdn/[$ref|value]
TransformOp fqdnParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::FQDN));
}

// +parse_file/[$ref|value]
TransformOp filePathParseBuilder(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::FILE));
}

// +parse_json/[$ref|value]
TransformOp jsonParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::JSON));
}

// +parse_xml/[$ref|value]
TransformOp xmlParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::XML));
}

// +parse_cvs/[$ref|value]/parser options
TransformOp csvParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::CSV));
}

// +parse_dvs/[$ref|value]/parser options
TransformOp dsvParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::DSV));
}

// +parse_key_value/[$ref|value]
TransformOp keyValueParseBuilder(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::KV));
}

// +parse_quoted/[$ref|value]
TransformOp quotedParseBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::QUOTED));
}

TransformOp betweenParseBuilder(const Reference& targetField,
                                const std::vector<OpArg>& opArgs,
                                const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::BETWEEN));
}

// +parse_alphanumeric/[$ref|value]
TransformOp alphanumericParseBuilder(const Reference& targetField,
                                     const std::vector<OpArg>& opArgs,
                                     const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return detail::specificHLPBuilder(targetField, opArgs, buildCtx, parserGetter(HLPParserType::ALPHANUMERIC));
}
} // namespace builder::builders::optransform
