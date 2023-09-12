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
constexpr auto REFERENCE_ANCHOR = '$';                ///< Char used to indicate a reference argument.
constexpr auto FUNCTION_HELPER_ARG_ANCHOR = ',';      ///< Char used to separate arguments in a function helper.
constexpr auto FUNCTION_HELPER_DEFAULT_ESCAPE = '\\'; ///< Char used to escape special characters in a function helper.
constexpr auto JSON_PATH_SEPARATOR = '.';             ///< Char used to separate levels in a JSON path.
constexpr auto CUSTOM_FIELD_ANCHOR = '~';             ///< Char used to indicate a field is a custom field.
constexpr auto VARIABLE_ANCHOR = '_';                 ///< Char used to indicate a field is a variable.
constexpr auto FIELD_EXTENDED = "_@#";                ///< Extended field path.
constexpr auto HELPER_NAME_EXTENDED = "_";            ///< Char used to indicate an extended helper name.
constexpr auto PARENTHESIS_OPEN = '(';                ///< Char used to open a group.
constexpr auto PARENTHESIS_CLOSE = ')';               ///< Char used to close a group.
constexpr auto SINGLE_QUOTE = '\'';                   ///< Char used to enclose a single-quoted string.

// Resource names
constexpr auto DECODER_PART = "decoder";         ///< The name of the decoder resource.
constexpr auto RULE_PART = "rule";               ///< The name of the rule resource.
constexpr auto OUTPUT_PART = "output";           ///< The name of the output resource.
constexpr auto FILTER_PART = "filter";           ///< The name of the filter resource.
constexpr auto INTEGRATION_PART = "integration"; ///< The name of the integration resource.
constexpr auto POLICY_PART = "policy";           ///< The name of the policy resource.

/**
 * @brief Check if a name corresponds to a decoder resource.
 * @param name The name to check.
 * @return True if the name corresponds to a decoder resource, false otherwise.
 */
inline bool isDecoder(const base::Name& name)
{
    return name.parts().front() == DECODER_PART;
}

/**
 * @brief Check if a name corresponds to a rule resource.
 * @param name The name to check.
 * @return True if the name corresponds to a rule resource, false otherwise.
 */
inline bool isRule(const base::Name& name)
{
    return name.parts().front() == RULE_PART;
}

/**
 * @brief Check if a name corresponds to an output resource.
 * @param name The name to check.
 * @return True if the name corresponds to an output resource, false otherwise.
 */
inline bool isOutput(const base::Name& name)
{
    return name.parts().front() == OUTPUT_PART;
}

/**
 * @brief Check if a name corresponds to a filter resource.
 * @param name The name to check.
 * @return True if the name corresponds to a filter resource, false otherwise.
 */
inline bool isFilter(const base::Name& name)
{
    return name.parts().front() == FILTER_PART;
}

/**
 * @brief Check if a name corresponds to an asset resource.
 * @param name The name to check.
 * @return True if the name corresponds to an asset resource, false otherwise.
 */
inline bool isAsset(const base::Name& name)
{
    return isDecoder(name) || isRule(name) || isOutput(name) || isFilter(name);
}

/**
 * @brief Check if a name corresponds to an integration resource.
 * @param name The name to check.
 * @return True if the name corresponds to an integration resource, false otherwise.
 */
inline bool isIntegration(const base::Name& name)
{
    return name.parts().front() == INTEGRATION_PART;
}

/**
 * @brief Check if a name corresponds to a policy resource.
 * @param name The name to check.
 * @return True if the name corresponds to a policy resource, false otherwise.
 */
inline bool isPolicy(const base::Name& name)
{
    return name.parts().front() == POLICY_PART;
}

// Integration sections
constexpr auto INTEGRATION_DECODERS = "decoders";         ///< The name of the decoders section in an integration.
constexpr auto INTEGRATION_RULES = "rules";               ///< The name of the rules section in an integration.
constexpr auto INTEGRATION_OUTPUTS = "outputs";           ///< The name of the outputs section in an integration.
constexpr auto INTEGRATION_FILTERS = "filters";           ///< The name of the filters section in an integration.
constexpr auto INTEGRATION_INTEGRATIONS = "integrations"; ///< The name of the integrations section in an integration.

/**
 * @brief Get the section name of a resource in an integration.
 * @param name The name of the resource.
 * @return The name of the section where the resource belongs.
 * @throws std::runtime_error if the name does not correspond to a known resource type.
 */
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
