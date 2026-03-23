#pragma once

#include <isca_policy.hpp>
#include <json.hpp>

#include <filesystem>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

/// @brief Compares two strings based on their length and then alphabetical order.
struct StringLengthGreater
{
    bool operator()(const std::string& a, const std::string& b) const
    {
        return a.length() > b.length() || (a.length() == b.length() && a < b);
    }
};

/// @brief A map for storing variables extracted from the YAML file, utilized for variable substitution during policy
/// parsing.
/// The map keys are the variable names, while the values are the corresponding substitutions. The map uses custom
/// comparator that prioritizes longer strings and, if equal in length, sorts the strings alphabetically.
using PolicyVariables = std::map<std::string, std::string, StringLengthGreater>;

/// @brief Function type for YAML to JSON conversion.
using YamlToJsonFunc = std::function<nlohmann::json(const std::string&)>;

/// @brief Parses and processes SCA policy files defined in YAML format.
///
/// This class is responsible for reading an SCA policy YAML file,
/// resolving variables, and converting it into an internal `SCAPolicy`
/// representation. It also extracts and transforms policy and check
/// data into JSON for further use.
class PolicyParser
{
    public:
        /// @brief Constructs a PolicyParser and loads the YAML file.
        /// @param filename Path to the YAML policy file.
        /// @param commandsTimeout Timeout for command execution.
        /// @param commandsEnabled Flag indicating whether commands are enabled.
        /// @param yamlToJsonFunc Function to convert YAML files to JSON strings.
        explicit PolicyParser(const std::filesystem::path& filename, const int commandsTimeout, const bool commandsEnabled, YamlToJsonFunc yamlToJsonFunc);

        /// @brief Parses the loaded policy file and extracts a SCAPolicy object.
        ///
        /// The method also populates the given JSON object with detailed
        /// information on policies and checks for reporting usage.
        ///
        /// @param policiesAndChecks JSON object to be filled with extracted data.
        /// @return A populated SCAPolicy object.
        std::unique_ptr<ISCAPolicy> ParsePolicy(nlohmann::json& policiesAndChecks);

    private:
        /// @brief Replaces variables in the JSON document with their values.
        /// @param jsonNode The JSON object to process.
        void ReplaceVariablesInJson(nlohmann::json& jsonNode);

        /// @brief Document loaded and converted from the YAML file.
        nlohmann::json m_jsonDocument;

        /// @brief Path to the original YAML file.
        std::filesystem::path m_filename;

        /// @brief Timeout for commands execution
        int m_commandsTimeout;

        /// @brief Flag indicating whether remote is enabled
        bool m_commandsEnabled;

        /// @brief Map of variables found in the YAML file, used for substitution.
        PolicyVariables m_variablesMap;

        /// @brief Function to convert YAML files to JSON strings.
        YamlToJsonFunc m_yamlToJsonFunc;
};
