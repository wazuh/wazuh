#include <sca_policy_parser.hpp>

#include <sca_policy.hpp>
#include <sca_policy_check.hpp>
#include <sca_utils.hpp>

#include <fstream>
#include <iostream>
#include <memory>
#include <json.hpp>
#include <sstream>

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
} // namespace

PolicyParser::PolicyParser(const std::filesystem::path& filename, const int commandsTimeout, const bool commandsEnabled, YamlToJsonFunc yamlToJsonFunc)
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
        m_jsonDocument = nlohmann::json{};
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

            policiesAndChecks["policies"].push_back(policyNode);

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
                if (requirementsNode.contains("title") && requirementsNode["title"].is_string())
                {
                    requirementsOutput["title"] = requirementsNode["title"];
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
            LoggingHelper::getInstance().log(LOG_ERROR, std::string("Failed to parse requirements. Error: ") + e.what());
            return nullptr;
        }
    }

    if (m_jsonDocument.contains("checks") && m_jsonDocument["checks"].is_array())
    {
        for (const auto& checkNode : m_jsonDocument["checks"])
        {
            try
            {
                Check check;

                if (checkNode.contains("id"))
                {
                    if (checkNode["id"].is_string())
                    {
                        check.id = checkNode["id"].get<std::string>();
                    }
                    else if (checkNode["id"].is_number())
                    {
                        check.id = std::to_string(checkNode["id"].get<int>());
                    }
                    else
                    {
                        // Log what type we actually got to help debug
                        LoggingHelper::getInstance().log(LOG_WARNING, "Check ID is not a string or number, unexpected type found");
                    }
                }

                if (checkNode.contains("condition") && checkNode["condition"].is_string())
                {
                    check.condition = checkNode["condition"].get<std::string>();
                    ValidateConditionString(check.condition);
                }

                // Create a copy of the check node for output with valid rules only
                nlohmann::json checkWithValidRules = checkNode;
                checkWithValidRules["rules"] = nlohmann::json::array();

                // Ensure the output JSON always has a string ID
                if (check.id.has_value())
                {
                    checkWithValidRules["id"] = check.id.value();
                }

                if (checkNode.contains("rules") && checkNode["rules"].is_array())
                {
                    for (const auto& rule : checkNode["rules"])
                    {
                        if (rule.is_string())
                        {
                            const std::string ruleStr = rule.get<std::string>();

                            if (auto ruleEvaluator = RuleEvaluatorFactory::CreateEvaluator(ruleStr, m_commandsTimeout, m_commandsEnabled))
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

                LoggingHelper::getInstance().log(LOG_DEBUG, "Check " + check.id.value_or("Invalid id") + " parsed.");

                checks.push_back(std::move(check));
                checkWithValidRules["policy_id"] = policyId;
                policiesAndChecks["checks"].push_back(checkWithValidRules);
            }
            catch (const std::exception& e)
            {
                LoggingHelper::getInstance().log(LOG_ERROR, std::string("Failed to parse a check. Skipping it. Error: ") + e.what());
                continue;
            }
        }
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Policy file does not contain checks");
        return nullptr;
    }

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
