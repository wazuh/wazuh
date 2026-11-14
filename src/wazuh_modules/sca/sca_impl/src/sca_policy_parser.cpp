#include <sca_policy_parser.hpp>

#include <sca_policy.hpp>
#include <sca_policy_check.hpp>
#include <sca_utils.hpp>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <json.hpp>
#include <sstream>
#include <unordered_set>

#include "logging_helper.hpp"

namespace
{
    void ValidateConditionString(const std::string& value)
    {
        if (!(value == "any" || value == "none" || value == "all"))
        {
            throw std::invalid_argument("Invalid condition: " + value);
        }
    }

    const std::unordered_set<std::string> ALLOWED_COMPLIANCE_KEYS = {
        "cmmc", "fedramp", "gdpr", "hipaa", "iso_27001", "nis2", "nist_800_171", "nist_800_53", "pci_dss", "tsc"};

    void ValidateComplianceKeys(nlohmann::json& checkJson, const std::string& checkId)
    {
        if (!checkJson.contains("compliance"))
        {
            return;
        }

        if (checkJson["compliance"].is_object())
        {
            std::vector<std::string> keysToRemove;

            for (const auto& [key, val] : checkJson["compliance"].items())
            {
                if (ALLOWED_COMPLIANCE_KEYS.find(key) == ALLOWED_COMPLIANCE_KEYS.end())
                {
                    LoggingHelper::getInstance().log(
                        LOG_WARNING, "Invalid compliance key '" + key + "' in check " + checkId + ", ignoring");
                    keysToRemove.push_back(key);
                }
            }

            for (const auto& key : keysToRemove)
            {
                checkJson["compliance"].erase(key);
            }
        }
        else if (!checkJson["compliance"].is_null())
        {
            LoggingHelper::getInstance().log(LOG_WARNING,
                                             "Unexpected compliance format in check " + checkId + ", ignoring");
            checkJson.erase("compliance");
        }
    }
} // namespace

PolicyParser::PolicyParser(const std::filesystem::path& filename,
                           const int commandsTimeout,
                           const bool commandsEnabled,
                           YamlToJsonFunc yamlToJsonFunc)
    : m_filename(filename)
    , m_commandsTimeout(commandsTimeout)
    , m_commandsEnabled(commandsEnabled)
    , m_yamlToJsonFunc(std::move(yamlToJsonFunc))
{
    try
    {
        m_jsonDocument = m_yamlToJsonFunc(filename.string());

        // Process variables if they exist
        if (m_jsonDocument.contains("variables") && m_jsonDocument["variables"].is_object())
        {
            for (const auto& [key, val] : m_jsonDocument["variables"].items())
            {
                if (val.is_string())
                {
                    m_variablesMap[key] = val.get<std::string>();
                }
            }

            ReplaceVariablesInJson(m_jsonDocument);
        }
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, std::string("Error parsing YAML file: ") + e.what());
        m_jsonDocument = nlohmann::json {};
    }
}

std::unique_ptr<ISCAPolicy> PolicyParser::ParsePolicy(nlohmann::json& policiesAndChecks)
{
    std::vector<Check> checks;
    Check requirements;

    std::string policyId;

    if (m_jsonDocument.contains("policy") && m_jsonDocument["policy"].is_object())
    {
        try
        {
            const auto& policyNode = m_jsonDocument["policy"];

            if (policyNode.contains("id") && policyNode["id"].is_string())
            {
                policyId = policyNode["id"].get<std::string>();
            }

            LoggingHelper::getInstance().log(LOG_DEBUG, "Policy parsed.");
        }
        catch (const std::exception& e)
        {
            LoggingHelper::getInstance().log(LOG_ERROR, std::string("Failed to parse policy: ") + e.what());
        }
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Policy file does not contain policy");
        return nullptr;
    }

    if (m_jsonDocument.contains("requirements") && m_jsonDocument["requirements"].is_object())
    {
        try
        {
            const auto& requirementsNode = m_jsonDocument["requirements"];

            if (requirementsNode.contains("condition") && requirementsNode["condition"].is_string())
            {
                requirements.condition = requirementsNode["condition"].get<std::string>();
                ValidateConditionString(requirements.condition);
            }
            else if (requirementsNode.contains("rules") && requirementsNode["rules"].is_array() &&
                     !requirementsNode["rules"].empty())
            {
                // Requirements rules cannot be evaluated without a condition, so the policy is rejected here
                // instead of failing when the scan reaches it.
                throw std::invalid_argument("Missing or invalid condition");
            }

            nlohmann::json requirementsOutput;

            if (requirementsNode.contains("rules") && requirementsNode["rules"].is_array())
            {
                for (const auto& rule : requirementsNode["rules"])
                {
                    if (rule.is_string())
                    {
                        const auto ruleString = rule.get<std::string>();
                        auto ruleEvaluator =
                            RuleEvaluatorFactory::CreateEvaluator(ruleString, m_commandsTimeout, m_commandsEnabled);

                        if (ruleEvaluator)
                        {
                            requirements.rules.push_back(std::move(ruleEvaluator));
                            requirementsOutput["rules"].push_back(ruleString);
                        }
                        else
                        {
                            LoggingHelper::getInstance().log(LOG_ERROR, "Failed to parse rule: " + ruleString);
                        }
                    }
                }
            }

            LoggingHelper::getInstance().log(LOG_DEBUG, "Requirements parsed.");

            if (!requirements.rules.empty() || !requirements.condition.empty())
            {
                // Support both 'name' (preferred) and 'title' (legacy) for backward compatibility
                if (requirementsNode.contains("name") && requirementsNode["name"].is_string())
                {
                    requirementsOutput["name"] = requirementsNode["name"];
                }
                else if (requirementsNode.contains("title") && requirementsNode["title"].is_string())
                {
                    requirementsOutput["name"] = requirementsNode["title"];
                }

                if (!requirements.condition.empty())
                {
                    requirementsOutput["condition"] = requirements.condition;
                }

                policiesAndChecks["requirements"] = requirementsOutput;
            }
        }
        catch (const std::exception& e)
        {
            LoggingHelper::getInstance().log(LOG_ERROR,
                                             "Failed to parse the requirements of policy file '" + m_filename.string() +
                                                 "'. Error: " + e.what());
            return nullptr;
        }
    }

    if (m_jsonDocument.contains("checks") && m_jsonDocument["checks"].is_array())
    {
        for (const auto& checkNode : m_jsonDocument["checks"])
        {
            std::string checkLabel = "without a valid id";

            try
            {
                Check check;
                std::string checkId;

                // The scan reports every result under the check id and evaluates the check with its condition, so a
                // check missing either one is skipped here rather than reaching the scan. A numeric id must be an
                // integer: a fractional one would be truncated onto another check's id.
                const auto idNode = checkNode.find("id");

                if (idNode != checkNode.end() && idNode->is_string())
                {
                    checkId = idNode->get<std::string>();
                }
                else if (idNode != checkNode.end() && idNode->is_number_unsigned())
                {
                    checkId = std::to_string(idNode->get<std::uint64_t>());
                }
                else if (idNode != checkNode.end() && idNode->is_number_integer())
                {
                    checkId = std::to_string(idNode->get<std::int64_t>());
                }
                else
                {
                    throw std::invalid_argument("Missing or invalid id");
                }

                check.id = checkId;
                checkLabel = "'" + checkId + "'";

                if (checkNode.contains("condition") && checkNode["condition"].is_string())
                {
                    check.condition = checkNode["condition"].get<std::string>();
                    ValidateConditionString(check.condition);
                }
                else
                {
                    throw std::invalid_argument("Missing or invalid condition");
                }

                // Create a copy of the check node for output with valid rules only
                nlohmann::json checkWithValidRules = checkNode;
                checkWithValidRules["rules"] = nlohmann::json::array();

                // Ensure the output JSON always has a string ID
                checkWithValidRules["id"] = checkId;

                if (checkNode.contains("rules") && checkNode["rules"].is_array())
                {
                    for (const auto& rule : checkNode["rules"])
                    {
                        if (rule.is_string())
                        {
                            const std::string ruleStr = rule.get<std::string>();

                            if (auto ruleEvaluator = RuleEvaluatorFactory::CreateEvaluator(
                                    ruleStr, m_commandsTimeout, m_commandsEnabled))
                            {
                                check.rules.push_back(std::move(ruleEvaluator));
                                checkWithValidRules["rules"].push_back(ruleStr);
                            }
                            else
                            {
                                LoggingHelper::getInstance().log(LOG_ERROR, "Failed to parse rule: " + ruleStr);
                            }
                        }
                    }
                }

                LoggingHelper::getInstance().log(LOG_DEBUG, "Check " + checkId + " parsed.");

                ValidateComplianceKeys(checkWithValidRules, checkId);

                checks.push_back(std::move(check));
                checkWithValidRules["policy_id"] = policyId;
                policiesAndChecks["checks"].push_back(checkWithValidRules);
            }
            catch (const std::exception& e)
            {
                LoggingHelper::getInstance().log(LOG_ERROR,
                                                 "Failed to parse check " + checkLabel + " of policy file '" +
                                                     m_filename.string() + "'. Skipping it. Error: " + e.what());
                continue;
            }
        }
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Policy file does not contain checks");
        return nullptr;
    }

    // Recorded only for a policy that is returned: a rejected one is not scanned, so it must not be stored either.
    policiesAndChecks["policies"].push_back(m_jsonDocument["policy"]);

    return std::make_unique<SCAPolicy>(policyId, std::move(requirements), std::move(checks));
}

// NOLINTNEXTLINE(misc-no-recursion)
void PolicyParser::ReplaceVariablesInJson(nlohmann::json& jsonNode)
{
    if (jsonNode.is_string())
    {
        std::string value = jsonNode.get<std::string>();

        for (const auto& pair : m_variablesMap)
        {
            size_t pos = 0;

            while ((pos = value.find(pair.first, pos)) != std::string::npos)
            {
                value.replace(pos, pair.first.length(), pair.second);
                pos += pair.second.length();
            }
        }

        jsonNode = value;
    }
    else if (jsonNode.is_object())
    {
        for (auto& [key, node] : jsonNode.items())
        {
            ReplaceVariablesInJson(node);
        }
    }
    else if (jsonNode.is_array())
    {
        for (auto& item : jsonNode)
        {
            ReplaceVariablesInJson(item);
        }
    }
}
