#pragma once

#include <isca_policy.hpp>

#include <iyaml_document.hpp>
#include <json.hpp>

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
    /// @param yamlDocument Optional pointer to an already loaded YAML document.
    explicit PolicyParser(const std::filesystem::path& filename, const int commandsTimeout, const bool commandsEnabled, std::unique_ptr<IYamlDocument> yamlDocument = nullptr);

    /// @brief Parses the loaded policy file and extracts a SCAPolicy object.
    ///
    /// The method also populates the given JSON object with detailed
    /// information on policies and checks for reporting usage.
    ///
    /// @param policiesAndChecks JSON object to be filled with extracted data.
    /// @return A populated SCAPolicy object.
    std::unique_ptr<ISCAPolicy> ParsePolicy(nlohmann::json& policiesAndChecks);

private:
    /// @brief Recursively replaces variables in the YAML node with their values.
    /// @param currentNode The YamlDocument to process.
    void ReplaceVariablesInNode(YamlNode& currentNode);

    /// @brief Document loaded from the YAML file.
    std::unique_ptr<IYamlDocument> m_yamlDocument;

    /// @brief Timeout for commands execution
    int m_commandsTimeout;

    /// @brief Flag indicating whether remote is enabled
    bool m_commandsEnabled;

    /// @brief Map of variables found in the YAML file, used for substitution.
    PolicyVariables m_variablesMap;
};
