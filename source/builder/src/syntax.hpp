#ifndef _BUILDER_SYNTAX_HPP
#define _BUILDER_SYNTAX_HPP

#include <base/json.hpp>
#include <base/name.hpp>

/**
 * @brief Defines syntax elements.
 *
 * This namespace contains all anchors and syntax elements that identify
 * different objects.
 */
namespace builder::syntax
{

namespace allowedfields
{
constexpr auto NAME_KEY = "name";                            ///< Key for the name of the document.
const auto NAME_PATH = json::Json::formatJsonPath(NAME_KEY); ///< Path to the name field in a document.
constexpr auto ALLOWED_FIELDS_KEY = "allowed_fields";        ///< Key for the allowed fields in a document.
const auto ALLOWED_FIELDS_PATH =
    json::Json::formatJsonPath(ALLOWED_FIELDS_KEY); ///< Path to the allowed fields in a document.
} // namespace allowedfields

// Asset syntax
namespace asset
{
constexpr auto NAME_KEY = "name";                     ///< Key for the name field in an asset.
constexpr auto METADATA_KEY = "metadata";             ///< Key for the metadata field in an asset.
constexpr auto PARENTS_KEY = "parents";               ///< Key for the parents field in an asset.
constexpr auto CHECK_KEY = "check";                   ///< Key for the check stage in an asset.
constexpr auto PARSE_KEY = "parse";                   ///< Key for the parse stage in an asset.
constexpr auto NORMALIZE_KEY = "normalize";           ///< Key for the normalize stage in an asset.
constexpr auto RULE_NORMALIZE_KEY = "rule_normalize"; ///< Key for the normalize stage in an asset.
constexpr auto MAP_KEY = "map";                       ///< Key for the map stage in an asset.
constexpr auto DEFINITIONS_KEY = "definitions";       ///< Key for the definitions stage in an asset.
constexpr auto OUTPUTS_KEY = "outputs";               ///< Key for the outputs stage in an asset.
constexpr auto FILE_OUTPUT_KEY = "file";              ///< Key for the file output stage in an asset.
constexpr auto FILE_OUTPUT_PATH_KEY = "path";         ///< Key for the file output path in an asset.
constexpr auto INDEXER_OUTPUT_KEY = "wazuh-indexer";  ///< Key for the INDEXER output stage in an asset.
constexpr auto INDEXER_OUTPUT_INDEX_KEY = "index";    ///< Key for the INDEXER output stage in an asset.

constexpr auto CONDITION_NAME =
    "condition"; ///< Name of the condition expression in the asset to be displayed in traces.
constexpr auto CONSEQUENCE_NAME =
    "stages";                        ///< Name of the consequence expression in the asset to be displayed in traces.
constexpr auto ASSET_NAME = "asset"; ///< Name of the asset expression to be displayed in traces.
} // namespace asset

// Field syntax
namespace field
{
constexpr auto REF_ANCHOR = '$';       ///< Char used to indicate a reference.
constexpr auto SEPARATOR = '.';        ///< Char used to separate levels in a fields path.
constexpr auto VAR_ANCHOR = '_';       ///< Char used to indicate a variable.
constexpr auto NAME_EXTENDED = "_@#-"; ///< Extended allowed chars in a field name.
constexpr auto DEFAULT_ESCAPE = '\\';  ///< Char used to escape special characters in a field name.
constexpr auto ESCAPED_CHARS = ".";    ///< Characters that can be escaped in a field name.
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
constexpr auto NUM_PARTS = 3;                    ///< Number of parts expected in the name.

/**
 * @brief Check if a name corresponds to a decoder resource.
 * @param name The name to check.
 * @param verifyParts Flag indicating whether to verify the parts of the name.
 * @return True if the name corresponds to a decoder resource, false otherwise.
 */
inline bool isDecoder(const base::Name& name, bool verifyParts = true)
{
    if (verifyParts)
    {
        return (name.parts().front() == DECODER_PART) && (name.parts().size() == NUM_PARTS);
    }
    return name.parts().front() == DECODER_PART;
}

/**
 * @brief Check if a name corresponds to a rule resource.
 * @param name The name to check.
 * @param verifyParts Flag indicating whether to verify the parts of the name.
 * @return True if the name corresponds to a rule resource, false otherwise.
 */
inline bool isRule(const base::Name& name, bool verifyParts = true)
{
    if (verifyParts)
    {
        return (name.parts().front() == RULE_PART) && (name.parts().size() == NUM_PARTS);
    }
    return name.parts().front() == RULE_PART;
}

/**
 * @brief Check if a name corresponds to an output resource.
 * @param name The name to check.
 * @param verifyParts Flag indicating whether to verify the parts of the name.
 * @return True if the name corresponds to an output resource, false otherwise.
 */
inline bool isOutput(const base::Name& name, bool verifyParts = true)
{
    if (verifyParts)
    {
        return (name.parts().front() == OUTPUT_PART) && (name.parts().size() == NUM_PARTS);
    }
    return name.parts().front() == OUTPUT_PART;
}

/**
 * @brief Check if a name corresponds to a filter resource.
 * @param name The name to check.
 * @param verifyParts Flag indicating whether to verify the parts of the name.
 * @return True if the name corresponds to a filter resource, false otherwise.
 */
inline bool isFilter(const base::Name& name, bool verifyParts = true)
{
    if (verifyParts)
    {
        return (name.parts().front() == FILTER_PART) && (name.parts().size() == NUM_PARTS);
    }
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

namespace integration
{
// Integration sections
constexpr auto DECODER_PATH = "/decoders";         ///< The name of the decoders section in an integration.
constexpr auto RULE_PATH = "/rules";               ///< The name of the rules section in an integration.
constexpr auto OUTPUT_PATH = "/outputs";           ///< The name of the outputs section in an integration.
constexpr auto FILTER_PATH = "/filters";           ///< The name of the filters section in an integration.
constexpr auto INTEGRATION_PATH = "/integrations"; ///< The name of the integrations section in an integration.
} // namespace integration

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
