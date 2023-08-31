#ifndef _SYNTAX_H
#define _SYNTAX_H

#include <name.hpp>

/**
 * @brief Defines syntax elements.
 *
 * This namespace contains all anchors and syntax elements that identify
 * different objects.
 */
namespace builder::internals::syntax
{

constexpr auto REFERENCE_ANCHOR = '$';
constexpr auto FUNCTION_HELPER_ARG_ANCHOR = ',';
constexpr auto FUNCTION_HELPER_DEFAULT_ESCAPE = '\\';
constexpr auto JSON_PATH_SEPARATOR = '.';
constexpr auto CUSTOM_FIELD_ANCHOR = '~';
constexpr auto VARIABLE_ANCHOR = '_';
constexpr auto FIELD_EXTENDED = "_@#";
constexpr auto HELPER_NAME_EXTENDED = "_";
constexpr auto PARENTHESIS_OPEN = '(';
constexpr auto PARENTHESIS_CLOSE = ')';
constexpr auto SINGLE_QUOTE = '\'';

// Resource names
constexpr auto DECODER_PART = "decoder";
constexpr auto RULE_PART = "rule";
constexpr auto OUTPUT_PART = "output";
constexpr auto FILTER_PART = "filter";
constexpr auto INTEGRATION_PART = "integration";
constexpr auto POLICY_PART = "policy";

inline bool isDecoder(const base::Name& name)
{
    return name.parts().front() == DECODER_PART;
}
inline bool isRule(const base::Name& name)
{
    return name.parts().front() == RULE_PART;
}
inline bool isOutput(const base::Name& name)
{
    return name.parts().front() == OUTPUT_PART;
}
inline bool isFilter(const base::Name& name)
{
    return name.parts().front() == FILTER_PART;
}
inline bool isAsset(const base::Name& name)
{
    return isDecoder(name) || isRule(name) || isOutput(name) || isFilter(name);
}

inline bool isIntegration(const base::Name& name)
{
    return name.parts().front() == INTEGRATION_PART;
}

inline bool isPolicy(const base::Name& name)
{
    return name.parts().front() == POLICY_PART;
}

// Integration sections
constexpr auto INTEGRATION_DECODERS = "decoders";
constexpr auto INTEGRATION_RULES = "rules";
constexpr auto INTEGRATION_OUTPUTS = "outputs";
constexpr auto INTEGRATION_FILTERS = "filters";
constexpr auto INTEGRATION_INTEGRATIONS = "integrations";

inline std::string getIntegrationSection(const base::Name& name)
{
    if (isDecoder(name))
    {
        return INTEGRATION_DECODERS;
    }
    else if (isRule(name))
    {
        return INTEGRATION_RULES;
    }
    else if (isOutput(name))
    {
        return INTEGRATION_OUTPUTS;
    }
    else if (isFilter(name))
    {
        return INTEGRATION_FILTERS;
    }
    else if (isIntegration(name))
    {
        return INTEGRATION_INTEGRATIONS;
    }
    else
    {
        throw std::runtime_error(fmt::format("Unknown integration section for name '{}'", name.toStr()));
    }
}

} // namespace builder::internals::syntax

#endif // _SYNTAX_H
