#ifndef _BUILDER_SYNTAX_HPP
#define _BUILDER_SYNTAX_HPP

#include <json/json.hpp>
#include <name.hpp>

/**
 * @brief Defines syntax elements.
 *
 * This namespace contains all anchors and syntax elements that identify
 * different objects.
 */
namespace builder::syntax
{

// Field syntax
namespace field
{
constexpr auto REF_ANCHOR = '$';      ///< Char used to indicate a reference.
constexpr auto SEPARATOR = '.';       ///< Char used to separate levels in a fields path.
constexpr auto VAR_ANCHOR = '_';      ///< Char used to indicate a variable.
constexpr auto NAME_EXTENDED = "_@#"; ///< Extended allowed chars in a field name.
} // namespace field

// Function helpers syntax
namespace helper
{
constexpr auto ARG_ANCHOR = ',';      ///< Char used to separate arguments in a function helper.
constexpr auto ARG_START = '(';       ///< Char used to start arguments in a function helper
constexpr auto ARG_END = ')';         ///< Char used to end arguments in a function helper
constexpr auto DEFAULT_ESCAPE = '\\'; ///< Char used to escape special characters in function helper arguments.
constexpr auto NAME_EXTENDED = "_";   ///< Extended allowed chars in a function helper name.
constexpr auto SINGLE_QUOTE = '\'';   ///< Char used to enclose a single-quoted string in helper arguments.
} // namespace helper

// Policy related syntax
namespace policy
{
const auto PATH_NAME = json::Json::formatJsonPath("name"); ///< Path to the name field in a policy.
const auto PATH_HASH = json::Json::formatJsonPath("hash"); ///< Path to the hash field in a policy.
const auto PATH_PARENTS =
    json::Json::formatJsonPath("default_parents");             ///< Path to the default parents field in a policy.
const auto PATH_ASSETS = json::Json::formatJsonPath("assets"); ///< Path to the assets field in a policy.
} // namespace policy

// Name related syntax
namespace name
{
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
} // namespace name

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
// inline std::string getIntegrationSection(const base::Name& name)
// {
//     if (isDecoder(name))
//     {
//         return INTEGRATION_DECODERS;
//     }
//     else if (isRule(name))
//     {
//         return INTEGRATION_RULES;
//     }
//     else if (isOutput(name))
//     {
//         return INTEGRATION_OUTPUTS;
//     }
//     else if (isFilter(name))
//     {
//         return INTEGRATION_FILTERS;
//     }
//     else if (isIntegration(name))
//     {
//         return INTEGRATION_INTEGRATIONS;
//     }
//     else
//     {
//         throw std::runtime_error(fmt::format("Unknown integration section for name '{}'", name.toStr()));
//     }
// }

} // namespace builder::syntax

#endif // _BUILDER_SYNTAX_HPP