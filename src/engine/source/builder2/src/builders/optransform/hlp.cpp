#include "builders/optransform/hlp.hpp"

#include <optional>

#include <fmt/format.h>

#include <hlp/hlp.hpp>
#include <logging/logging.hpp>

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

/**
 * @brief Resolve the string reference or return the value if it is not a reference
 *
 * @param event
 * @param source
 * @return std::string The value of the reference or the value itself. nullptr if the
 * reference is not found or the value is not a string
 */
inline std::optional<std::string> resolvedValue(base::ConstEvent event, const OpArg& source)
{
    if (source->isReference())
    {
        auto reference = event->getString(std::static_pointer_cast<Reference>(source)->jsonPath());
        if (!reference)
        {
            return std::nullopt;
        }
        return std::move(reference);
    }

    return std::static_pointer_cast<Value>(source)->value().getString();
}

TransformOp specificHLPBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx,
                               HLPParserType type)
{
    // Check if the number of parameters is correct
    utils::assertSize(opArgs, 1, utils::MAX_OP_ARGS);
    utils::assertRef(opArgs, 0);

    // Get the source
    const auto source = opArgs[0];
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
    switch (type)
    {
        case HLPParserType::ALPHANUMERIC: parser = hlp::parsers::getAlphanumericParser(params); break;
        case HLPParserType::BOOL: parser = hlp::parsers::getBoolParser(params); break;
        case HLPParserType::BYTE: parser = hlp::parsers::getByteParser(params); break;
        case HLPParserType::LONG: parser = hlp::parsers::getLongParser(params); break;
        case HLPParserType::FLOAT: parser = hlp::parsers::getFloatParser(params); break;
        case HLPParserType::DOUBLE: parser = hlp::parsers::getDoubleParser(params); break;
        case HLPParserType::SCALED_FLOAT: parser = hlp::parsers::getScaledFloatParser(params); break;
        case HLPParserType::QUOTED: parser = hlp::parsers::getQuotedParser(params); break;
        case HLPParserType::BETWEEN: parser = hlp::parsers::getBetweenParser(params); break;
        case HLPParserType::BINARY: parser = hlp::parsers::getBinaryParser(params); break;
        case HLPParserType::DATE: parser = hlp::parsers::getDateParser(params); break;
        case HLPParserType::IP: parser = hlp::parsers::getIPParser(params); break;
        case HLPParserType::URI: parser = hlp::parsers::getUriParser(params); break;
        case HLPParserType::USERAGENT: parser = hlp::parsers::getUAParser(params); break;
        case HLPParserType::FQDN: parser = hlp::parsers::getFQDNParser(params); break;
        case HLPParserType::FILE: parser = hlp::parsers::getFilePathParser(params); break;
        case HLPParserType::JSON: parser = hlp::parsers::getJSONParser(params); break;
        case HLPParserType::XML: parser = hlp::parsers::getXMLParser(params); break;
        case HLPParserType::DSV: parser = hlp::parsers::getDSVParser(params); break;
        case HLPParserType::CSV: parser = hlp::parsers::getCSVParser(params); break;
        case HLPParserType::KV: parser = hlp::parsers::getKVParser(params); break;
        default: throw std::logic_error("Invalid HLP parser type");
    }

    // Parser must consume all input, add EOF parser
    parser = hlp::parser::combinator::all({parser, hlp::parsers::getEofParser({.name = "EOF"})});

    const auto traceName = buildCtx->context().opName;
    const auto successTrace = fmt::format("{} -> Success", traceName);
    const auto failureTrace = fmt::format("{} -> Failure: ", traceName);
    const auto failureTrace1 = fmt::format("{} -> Failure: parameter is not a string or it doesn't exist", traceName);
    const auto failureTrace3 = fmt::format("{} -> Failure: There is still text to analyze after parsing", traceName);

    // Return Op
    return [=, parser = std::move(parser)](base::Event event) -> TransformResult
    {
        // Check if source is a reference
        const auto sourceValue = resolvedValue(event, source);
        if (!sourceValue)
        {
            return base::result::makeFailure(event, failureTrace1);
        }

        // Parse source
        auto error = hlp::parser::run(parser, sourceValue.value(), *event);
        if (error)
        {
            return base::result::makeFailure(event, failureTrace + error.value().message);
        }

        return base::result::makeSuccess(event, successTrace);
    };
}

} // namespace

namespace builder::builders::optransform
{

//*************************************************
//*         HLP Specific parser Helpers           *
//*************************************************
// +parse_bool/[$ref|value]
TransformOp boolParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::BOOL);
}

// +parse_byte/[$ref|value]
TransformOp byteParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::BYTE);
}

// +parse_long/[$ref|value]
TransformOp longParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::LONG);
}

// +parse_float/[$ref|value]
TransformOp floatParseBuilder(const Reference& targetField,
                              const std::vector<OpArg>& opArgs,
                              const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::FLOAT);
}

// +parse_double/[$ref|value]
TransformOp doubleParseBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::DOUBLE);
}

// +parse_binary/[$ref|value]
TransformOp binaryParseBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::BINARY);
}

// +parse_date/[$ref|value]
TransformOp dateParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::DATE);
}

// +parse_ip/[$ref|value]
TransformOp ipParseBuilder(const Reference& targetField,
                           const std::vector<OpArg>& opArgs,
                           const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::IP);
}

// +parse_uri/[$ref|value]
TransformOp uriParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::URI);
}

// +parse_useragent/[$ref|value]
TransformOp userAgentParseBuilder(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::USERAGENT);
}

// +parse_fqdn/[$ref|value]
TransformOp fqdnParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::FQDN);
}

// +parse_file/[$ref|value]
TransformOp filePathParseBuilder(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::FILE);
}

// +parse_json/[$ref|value]
TransformOp jsonParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::JSON);
}

// +parse_xml/[$ref|value]
TransformOp xmlParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::XML);
}

// +parse_cvs/[$ref|value]/parser options
TransformOp csvParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::CSV);
}

// +parse_dvs/[$ref|value]/parser options
TransformOp dsvParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::DSV);
}

// +parse_key_value/[$ref|value]
TransformOp keyValueParseBuilder(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::KV);
}

// +parse_quoted/[$ref|value]
TransformOp quotedParseBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::QUOTED);
}

TransformOp betweenParseBuilder(const Reference& targetField,
                                const std::vector<OpArg>& opArgs,
                                const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::BETWEEN);
}

// +parse_alphanumeric/[$ref|value]
TransformOp alphanumericParseBuilder(const Reference& targetField,
                                     const std::vector<OpArg>& opArgs,
                                     const std::shared_ptr<const IBuildCtx>& buildCtx)
{
    return specificHLPBuilder(targetField, opArgs, buildCtx, HLPParserType::ALPHANUMERIC);
}
} // namespace builder::builders::optransform
