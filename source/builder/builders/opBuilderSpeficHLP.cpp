/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "opBuilderSpeficHLP.hpp"

#include <optional>
#include <string>
#include <variant>
#include <vector>

#include <hlp/hlp.hpp>
#include <logging/logging.hpp>

#include "baseHelper.hpp"
#include "syntax.hpp"

using builder::internals::syntax::REFERENCE_ANCHOR;

namespace
{

enum class HLPParserType
{
    BOOL,         // OK
    BYTE,         // OK
    LONG,         // OK
    FLOAT,        // OK
    DOUBLE,       // OK
    SCALED_FLOAT, // OK
    TEXT,         // Unimplemented
    BASE64,       // OK
    DATE,         // OK
    IP,           // OK
    URI,          // Ok, parser does not work but helper does
    USER_AGENT,   // Ok, parser does not work but helper does
    FQDN,         // Ok, parser does not work but helper does
    FILE_PATH,    // OK
    JSON,         // Ok
    XML,          // Test 1 parametro opcional, exepcion no controlada
    CSV,          // Unimplemented
    KEY_VALUE,    // Unimplemented
};

/**
 * @brief Resolve the string reference or return the value if it is not a reference
 *
 * @param event
 * @param source
 * @return std::string The value of the reference or the value itself. nullptr if the
 * reference is not found or the value is not a string
 */
inline std::optional<std::string> resolvedValue(const base::Event& event,
                                                const helper::base::Parameter& source)
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

base::Expression opBuilderSpecificHLPTypeParse(const std::any& definition,
                                                HLPParserType type)
{
    auto [targetField, name, rawParameters] = helper::base::extractDefinition(definition);
    auto parameters = helper::base::processParameters(rawParameters);

    if (parameters.empty())
    {
        throw std::runtime_error("Invalid number of parameters for operation '" + name
                                 + "'");
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
            throw std::runtime_error("Invalid parameter type for operation '" + name
                                     + "'");
        }
        hlpOptionsList.emplace_back(parameter.m_value);
    }

    parsec::Parser<json::Json> parser;
    switch (type)
    {
        case HLPParserType::BOOL:
            parser = hlp::getBoolParser({""}, hlpOptionsList);
            break;
        case HLPParserType::BYTE:
            parser = hlp::getByteParser({""}, hlpOptionsList);
            break;
        case HLPParserType::LONG:
            parser = hlp::getLongParser({""}, hlpOptionsList);
            break;
        case HLPParserType::FLOAT:
            parser = hlp::getFloatParser({""}, hlpOptionsList);
            break;
        case HLPParserType::DOUBLE:
            parser = hlp::getDoubleParser({""}, hlpOptionsList);
            break;
        case HLPParserType::SCALED_FLOAT:
            parser = hlp::getScaledFloatParser({""}, hlpOptionsList);
            break;
        case HLPParserType::BASE64:
            parser = hlp::getBinaryParser({""}, hlpOptionsList);
            break;
        case HLPParserType::DATE:
            parser = hlp::getDateParser({""}, hlpOptionsList);
            break;
        case HLPParserType::IP:
            parser = hlp::getIPParser({""}, hlpOptionsList);
            break;
        case HLPParserType::URI:
            parser = hlp::getUriParser({""}, hlpOptionsList);
            break;
        case HLPParserType::USER_AGENT:
            parser = hlp::getUAParser({""}, hlpOptionsList);
            break;
        case HLPParserType::FQDN:
            parser = hlp::getFQDNParser({""}, hlpOptionsList);
            break;
        case HLPParserType::FILE_PATH:
            parser = hlp::getFilePathParser({""}, hlpOptionsList);
            break;
        case HLPParserType::JSON:
            parser = hlp::getJSONParser({""}, hlpOptionsList);
            break;
        case HLPParserType::XML:
            parser = hlp::getXMLParser({""}, hlpOptionsList);
            break;
        case HLPParserType::CSV:
            parser = hlp::getCSVParser({""}, hlpOptionsList);
            break;
        case HLPParserType::KEY_VALUE:
            parser = hlp::getKVParser({""}, hlpOptionsList);
            break;
        default:
            throw std::logic_error("Invalid HLP parser type");
    }

    const auto traceName =
        helper::base::formatHelperFilterName(name, targetField, parameters);
    const auto successTrace = fmt::format("[{}] -> Success", traceName);
    const auto failureTrace1 = fmt::format(
        "[{}] -> Failure: parameter is not a string or it doesn't exist", traceName);
    const auto failureTrace2 = fmt::format("[{}] -> Failure: {}", traceName, "{}");

    // Return Term
    return base::Term<base::EngineOp>::create(
        name,
        [=,
         targetField = std::move(targetField),
         parser = std::move(parser),
         source = std::move(source)](
            base::Event event) -> base::result::Result<base::Event>
        {
            // Check if source is a reference
            const auto sourceValue = resolvedValue(event, source);
            if (!sourceValue)
            {
                return base::result::makeFailure(event, failureTrace1);
            }

            // Parse source
            const auto result = parser(sourceValue.value(), 0);
            if (result.failure())
            {
                const auto tracerFailure = fmt::format(failureTrace2, result.error().msg);
                return base::result::makeFailure(event, tracerFailure);
            }
            // Add result to event
            event->set(targetField, result.value());
            return base::result::makeSuccess(event, successTrace);
        });
}

} // namespace

namespace builder::internals::builders
{

//*************************************************
//*         HLP Specific parser Helpers           *
//*************************************************
// +parser_bool/[$ref|value]
base::Expression opBuilderSpecificHLPBoolParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::BOOL);
}

// +parser_byte/[$ref|value]
base::Expression opBuilderSpecificHLPByteParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::BYTE);
}

// +parser_long/[$ref|value]
base::Expression opBuilderSpecificHLPLongParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::LONG);
}

// +parser_float/[$ref|value]
base::Expression opBuilderSpecificHLPFloatParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::FLOAT);
}

// +parser_double/[$ref|value]
base::Expression opBuilderSpecificHLPDoubleParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::DOUBLE);
}

// +parser_base64/[$ref|value]
base::Expression opBuilderSpecificHLPBase64Parse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::BASE64);
}

// +parser_date/[$ref|value]
base::Expression opBuilderSpecificHLPDateParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::DATE);
}

// +parser_ip/[$ref|value]
base::Expression opBuilderSpecificHLPIPParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::IP);
}

// +parser_uri/[$ref|value]
base::Expression opBuilderSpecificHLPURIParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::URI);
}

// +parser_user_agent/[$ref|value]
base::Expression opBuilderSpecificHLPUserAgentParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::USER_AGENT);
}

// +parser_fqdn/[$ref|value]
base::Expression opBuilderSpecificHLPFQDNParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::FQDN);
}

// +parser_file_path/[$ref|value]
base::Expression opBuilderSpecificHLPFilePathParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::FILE_PATH);
}

// +parser_json/[$ref|value]
base::Expression opBuilderSpecificHLPJSONParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::JSON);
}

// +parser_xml/[$ref|value]
base::Expression opBuilderSpecificHLPXMLParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::XML);
}

// +parser_cvs/[$ref|value]/parser options
base::Expression opBuilderSpecificHLPCSVParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::CSV);
}

// +parser_keyvalue/[$ref|value]
base::Expression opBuilderSpecificHLPKeyValueParse(const std::any& definition)
{
    return opBuilderSpecificHLPTypeParse(definition, HLPParserType::KEY_VALUE);
}


} // namespace builder::internals::builders
