#include "opBuilderSpeficHLP.hpp"

#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <defs/idefinitions.hpp>
#include <hlp/hlp.hpp>
#include <logging/logging.hpp>

#include "baseHelper.hpp"
#include "syntax.hpp"

using builder::internals::syntax::REFERENCE_ANCHOR;

namespace
{

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
inline std::optional<std::string> resolvedValue(const base::Event& event, const helper::base::Parameter& source)
{
    if (source.m_type == helper::base::Parameter::Type::REFERENCE)
    {
        auto reference = event->getString(source.m_value);
        if (!reference)
        {
            return std::nullopt;
        }
        return std::move(reference);
    }
    return source.m_value;
}

base::Expression opBuilderSpecificHLPTypeParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               HLPParserType type,
                                               std::shared_ptr<defs::IDefinitions> definitions)
{
    auto parameters = helper::base::processParameters(rawName, rawParameters, definitions);

    if (parameters.empty())
    {
        throw std::runtime_error("Invalid number of parameters for operation '" + rawName + "'");
    }
    const auto source = parameters[0];
    parameters.erase(parameters.begin());

    hlp::Options hlpOptionsList {};
    hlpOptionsList.reserve(parameters.size());
    // Check if the parameter is a reference
    for (auto& parameter : parameters)
    {
        if (parameter.m_type == helper::base::Parameter::Type::REFERENCE)
        {
            throw std::runtime_error("Invalid parameter type for operation '" + rawName + "'");
        }
        hlpOptionsList.emplace_back(parameter.m_value);
    }

    hlp::parser::Parser parser;
    hlp::Params params{.name = "parser", .targetField = targetField, .stop = {""}, .options = hlpOptionsList};
    switch (type)
    {
        // case HLPParserType::ALPHANUMERIC: parser = hlp::parsers::getAlphanumericParser(params); break;
        // case HLPParserType::BOOL: parser = hlp::parsers::getBoolParser(params); break;
        case HLPParserType::BYTE: parser = hlp::parsers::getByteParser(params); break;
        case HLPParserType::LONG: parser = hlp::parsers::getLongParser(params); break;
        case HLPParserType::FLOAT: parser = hlp::parsers::getFloatParser(params); break;
        case HLPParserType::DOUBLE: parser = hlp::parsers::getDoubleParser(params); break;
        case HLPParserType::SCALED_FLOAT: parser = hlp::parsers::getScaledFloatParser(params); break;
        // case HLPParserType::QUOTED: parser = hlp::parsers::getQuotedParser(params); break;
        // case HLPParserType::BETWEEN: parser = hlp::parsers::getBetweenParser(params); break;
        // case HLPParserType::BINARY: parser = hlp::parsers::getBinaryParser(params); break;
        // case HLPParserType::DATE: parser = hlp::parsers::getDateParser(params); break;
        // case HLPParserType::IP: parser = hlp::parsers::getIPParser(params); break;
        // case HLPParserType::URI: parser = hlp::parsers::getUriParser(params); break;
        // case HLPParserType::USERAGENT: parser = hlp::parsers::getUAParser(params); break;
        // case HLPParserType::FQDN: parser = hlp::parsers::getFQDNParser(params); break;
        // case HLPParserType::FILE: parser = hlp::parsers::getFilePathParser(params); break;
        // case HLPParserType::JSON: parser = hlp::parsers::getJSONParser(params); break;
        // case HLPParserType::XML: parser = hlp::parsers::getXMLParser(params); break;
        // case HLPParserType::DSV: parser = hlp::parsers::getDSVParser(params); break;
        // case HLPParserType::CSV: parser = hlp::parsers::getCSVParser(params); break;
        // case HLPParserType::KV: parser = hlp::parsers::getKVParser(params); break;
        default: throw std::logic_error("Invalid HLP parser type");
    }

    // Parser must consume all input, add EOF parser
    parser = hlp::parser::combinator::all({parser, hlp::parsers::getEofParser({.name = "EOF"})});

    const std::string traceName {helper::base::formatHelperName(rawName, targetField, parameters)};
    const std::string successTrace {fmt::format("[{}] -> Success", traceName)};
    const std::string failureTrace {fmt::format("[{}] -> Failure: ", traceName)};
    const std::string failureTrace1 {
        fmt::format("[{}] -> Failure: parameter is not a string or it doesn't exist", traceName)};
    const std::string failureTrace3 {
        fmt::format("[{}] -> Failure: There is still text to analyze after parsing", traceName)};

    // Return Term
    return base::Term<base::EngineOp>::create(
        traceName,
        [=, parser = std::move(parser), source = std::move(source)](
            base::Event event) -> base::result::Result<base::Event>
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
        });
}

} // namespace

namespace builder::internals::builders
{

//*************************************************
//*         HLP Specific parser Helpers           *
//*************************************************
// +parse_bool/[$ref|value]
base::Expression opBuilderSpecificHLPBoolParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::BOOL, definitions);
}

// +parse_byte/[$ref|value]
base::Expression opBuilderSpecificHLPByteParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::BYTE, definitions);
}

// +parse_long/[$ref|value]
base::Expression opBuilderSpecificHLPLongParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::LONG, definitions);
}

// +parse_float/[$ref|value]
base::Expression opBuilderSpecificHLPFloatParse(const std::string& targetField,
                                                const std::string& rawName,
                                                const std::vector<std::string>& rawParameters,
                                                std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::FLOAT, definitions);
}

// +parse_double/[$ref|value]
base::Expression opBuilderSpecificHLPDoubleParse(const std::string& targetField,
                                                 const std::string& rawName,
                                                 const std::vector<std::string>& rawParameters,
                                                 std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::DOUBLE, definitions);
}

// +parse_binary/[$ref|value]
base::Expression opBuilderSpecificHLPBinaryParse(const std::string& targetField,
                                                 const std::string& rawName,
                                                 const std::vector<std::string>& rawParameters,
                                                 std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::BINARY, definitions);
}

// +parse_date/[$ref|value]
base::Expression opBuilderSpecificHLPDateParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::DATE, definitions);
}

// +parse_ip/[$ref|value]
base::Expression opBuilderSpecificHLPIPParse(const std::string& targetField,
                                             const std::string& rawName,
                                             const std::vector<std::string>& rawParameters,
                                             std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::IP, definitions);
}

// +parse_uri/[$ref|value]
base::Expression opBuilderSpecificHLPURIParse(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::URI, definitions);
}

// +parse_useragent/[$ref|value]
base::Expression opBuilderSpecificHLPUserAgentParse(const std::string& targetField,
                                                    const std::string& rawName,
                                                    const std::vector<std::string>& rawParameters,
                                                    std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::USERAGENT, definitions);
}

// +parse_fqdn/[$ref|value]
base::Expression opBuilderSpecificHLPFQDNParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::FQDN, definitions);
}

// +parse_file/[$ref|value]
base::Expression opBuilderSpecificHLPFilePathParse(const std::string& targetField,
                                                   const std::string& rawName,
                                                   const std::vector<std::string>& rawParameters,
                                                   std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::FILE, definitions);
}

// +parse_json/[$ref|value]
base::Expression opBuilderSpecificHLPJSONParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::JSON, definitions);
}

// +parse_xml/[$ref|value]
base::Expression opBuilderSpecificHLPXMLParse(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::XML, definitions);
}

// +parse_cvs/[$ref|value]/parser options
base::Expression opBuilderSpecificHLPCSVParse(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::CSV, definitions);
}

// +parse_dvs/[$ref|value]/parser options
base::Expression opBuilderSpecificHLPDSVParse(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::DSV, definitions);
}

// +parse_key_value/[$ref|value]
base::Expression opBuilderSpecificHLPKeyValueParse(const std::string& targetField,
                                                   const std::string& rawName,
                                                   const std::vector<std::string>& rawParameters,
                                                   std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::KV, definitions);
}

// +parse_quoted/[$ref|value]
base::Expression opBuilderSpecificHLPQuotedParse(const std::string& targetField,
                                                 const std::string& rawName,
                                                 const std::vector<std::string>& rawParameters,
                                                 std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::QUOTED, definitions);
}

base::Expression opBuilderSpecificHLPBetweenParse(const std::string& targetField,
                                                  const std::string& rawName,
                                                  const std::vector<std::string>& rawParameters,
                                                  std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::BETWEEN, definitions);
}

// +parse_alphanumeric/[$ref|value]
base::Expression opBuilderSpecificHLPAlphanumericParse(const std::string& targetField,
                                                       const std::string& rawName,
                                                       const std::vector<std::string>& rawParameters,
                                                       std::shared_ptr<defs::IDefinitions> definitions)
{
    return opBuilderSpecificHLPTypeParse(targetField, rawName, rawParameters, HLPParserType::ALPHANUMERIC, definitions);
}
} // namespace builder::internals::builders
