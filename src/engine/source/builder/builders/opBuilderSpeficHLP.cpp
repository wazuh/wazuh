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
    auto source = parameters[0];
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

    parsec::Parser<hlp::jFnList> parser;
    /*
    switch (type)
    {
        case HLPParserType::ALPHANUMERIC: parser = hlp::getAlphanumericParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::BOOL: parser = hlp::getBoolParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::BYTE: parser = hlp::getByteParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::LONG: parser = hlp::getLongParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::FLOAT: parser = hlp::getFloatParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::DOUBLE: parser = hlp::getDoubleParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::SCALED_FLOAT: parser = hlp::getScaledFloatParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::QUOTED: parser = hlp::getQuotedParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::BETWEEN: parser = hlp::getBetweenParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::BINARY: parser = hlp::getBinaryParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::DATE: parser = hlp::getDateParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::IP: parser = hlp::getIPParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::URI: parser = hlp::getUriParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::USERAGENT: parser = hlp::getUAParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::FQDN: parser = hlp::getFQDNParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::FILE: parser = hlp::getFilePathParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::JSON: parser = hlp::getJSONParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::XML: parser = hlp::getXMLParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::DSV: parser = hlp::getDSVParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::CSV: parser = hlp::getCSVParser({}, {""}, hlpOptionsList); break;
        case HLPParserType::KV: parser = hlp::getKVParser({}, {""}, hlpOptionsList); break;
        default: throw std::logic_error("Invalid HLP parser type");
    }
    */
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
        [=, targetField = std::move(targetField), parser = std::move(parser), source = std::move(source)](
            base::Event event) -> base::result::Result<base::Event>
        {
            // Check if source is a reference
            const auto sourceValue = resolvedValue(event, source);
            if (!sourceValue)
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            // Parse source
            auto state = parsec::ParserState(sourceValue.value(), false); // Debug level
            const auto result = parser(state);
            // TODO: move this to a function in parsec
            std::string trace {};
            if (result.hasTraces())
            {
                trace += ":\n";
                for (const auto& t : result.getTraces())
                {
                    // TODO: check if the order is necesary
                    // Format: [order]: | offset: [offset] | [message]
                    trace += fmt::format("{:4}: | offset: {:3} | {}\n", t.getOrder(), t.getOffset(), t.getMessage());
                }
                trace.pop_back(); // Remove last \n
            }

            if (result.isFailure())
            {
                return base::result::makeFailure(event, failureTrace + trace);
            }

            // Check if has a remaining string
            if (result.getParserState().getRemainingSize() != 0)
            {
                return base::result::makeFailure(event, failureTrace3);
            }

            // Add result to event

            for (const auto& fn : result.getValue())
            {
                fn(*event); // The target field is set in parser builder
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
