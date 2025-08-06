#include <sca_policy_parser.hpp>

#include <sca_policy.hpp>
#include <sca_policy_check.hpp>

#include <yaml_document.hpp>
#include <yaml_node.hpp>

#include <fstream>
#include <iostream>
#include <memory>
#include <json.hpp>
#include <sstream>

#include "logging_helper.hpp"

namespace
{
    std::string Join(const std::vector<std::string>& elements, const std::string& separator)
    {
        std::ostringstream oss;
        for (size_t i = 0; i < elements.size(); ++i)
        {
            if (i > 0)
            {
                oss << separator;
            }
            oss << elements[i];
        }
        return oss.str();
    }

    // NOLINTNEXTLINE(misc-no-recursion)
    nlohmann::json YamlNodeToJson(const YamlNode& yamlNode)
    {
        if (yamlNode.IsScalar())
        {
            return yamlNode.AsString();
        }
        else if (yamlNode.IsSequence())
        {
            std::vector<std::string> values;
            const auto items = yamlNode.AsSequence();
            for (const auto& item : items)
            {
                if (item.IsScalar())
                {
                    values.push_back(item.AsString());
                }
                else if (item.IsMap())
                {
                    for (const auto& [key, subitem] : item.AsMap())
                    {
                        if (subitem.IsSequence())
                        {
                            const auto subitems = subitem.AsSequence();
                            for (const auto& val : subitems)
                            {
                                values.emplace_back(key + ":" + val.AsString());
                            }
                        }
                    }
                }
            }
            return Join(values, ", ");
        }
        else if (yamlNode.IsMap())
        {
            nlohmann::json j;
            for (const auto& [key, node] : yamlNode.AsMap())
            {
                j[key] = YamlNodeToJson(node);
            }
            return j;
        }

        return nullptr;
    }

    void ValidateConditionString(const std::string& value)
    {
        if (!(value == "any" || value == "none" || value == "all"))
        {
            throw std::invalid_argument("Invalid condition: " + value);
        }
    }
} // namespace

// NOLINTNEXTLINE(performance-unnecessary-value-param)
PolicyParser::PolicyParser(const std::filesystem::path& filename, const int commandsTimeout, const bool commandsEnabled, std::unique_ptr<IYamlDocument> yamlDocument)
: m_commandsTimeout(commandsTimeout)
, m_commandsEnabled(commandsEnabled)
{
    if (yamlDocument)
    {
        m_yamlDocument = std::move(yamlDocument);
    }
    else
    {
        m_yamlDocument = std::make_unique<YamlDocument>(filename);
    }

    try
    {
        if (!m_yamlDocument->IsValidDocument())
        {
            throw std::runtime_error("The file does not contain a valid YAML structure.");
        }

        YamlNode root = m_yamlDocument->GetRoot();

        if (root.HasKey("variables"))
        {
            const auto variablesNode = root["variables"];

            for (const auto& [key, val] : variablesNode.AsMap())
            {
                m_variablesMap[key] = val.AsString();
            }

            ReplaceVariablesInNode(root);
        }
    }
    catch (const std::exception& e)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, std::string("Error parsing YAML file: ") + e.what());
    }
}

std::unique_ptr<ISCAPolicy> PolicyParser::ParsePolicy(nlohmann::json& policiesAndChecks)
{
    std::vector<Check> checks;
    Check requirements;

    std::string policyId;

    const YamlNode root = m_yamlDocument->GetRoot();

    if (root.HasKey("policy"))
    {
        try
        {
            const auto policyNode = root["policy"];
            policyId = policyNode["id"].AsString();
            policiesAndChecks["policies"].push_back(YamlNodeToJson(policyNode));

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

    if (root.HasKey("requirements"))
    {
        try
        {
            const auto requirementsNode = root["requirements"];
            requirements.condition = requirementsNode["condition"].AsString();
            ValidateConditionString(requirements.condition);

            const auto rules = requirementsNode["rules"].AsSequence();

            for (const auto& rule : rules)
            {
                std::unique_ptr<IRuleEvaluator> RuleEvaluator = RuleEvaluatorFactory::CreateEvaluator(rule.AsString(), m_commandsTimeout, m_commandsEnabled);
                if (RuleEvaluator != nullptr)
                {
                    requirements.rules.push_back(std::move(RuleEvaluator));
                }
                else
                {
                    LoggingHelper::getInstance().log(LOG_ERROR, "Failed to parse rule: " + rule.AsString());
                }
            }
            LoggingHelper::getInstance().log(LOG_DEBUG, "Requirements parsed.");
        }
        catch (const std::exception& e)
        {
            std::stringstream ss;
            LoggingHelper::getInstance().log(LOG_ERROR, std::string("Failed to parse requirements. Error: ") + e.what());
            return nullptr;
        }
    }

    if (root.HasKey("checks"))
    {
        const auto checksNode = root["checks"].AsSequence();
        for (const auto& checkNode : checksNode)
        {
            try
            {
                Check check;
                check.id = checkNode["id"].AsString();
                check.condition = checkNode["condition"].AsString();
                ValidateConditionString(check.condition);

                // create new document with valid rules
                auto newDoc = checkNode.Clone();
                auto newRoot = newDoc.GetRoot();

                // remove existing rules and create empty sequence
                auto checkWithValidRules = newRoot;
                newRoot.RemoveKey("rules");
                newRoot.CreateEmptySequence("rules");

                if (checkNode.HasKey("rules"))
                {
                    const auto rules = checkNode["rules"].AsSequence();

                    for (const auto& rule : rules)
                    {
                        const auto ruleStr = rule.AsString();

                        if (auto ruleEvaluator = RuleEvaluatorFactory::CreateEvaluator(ruleStr, m_commandsTimeout, m_commandsEnabled))
                        {
                            check.rules.push_back(std::move(ruleEvaluator));
                            checkWithValidRules["rules"].AppendToSequence(ruleStr);
                        }
                        else
                        {
                            LoggingHelper::getInstance().log(LOG_ERROR, "Failed to parse rule: " + ruleStr);
                        }
                    }
                }

                LoggingHelper::getInstance().log(LOG_DEBUG, "Check " + check.id.value_or("Invalid id") + " parsed.");

                checks.push_back(std::move(check));
                nlohmann::json checkJson = YamlNodeToJson(checkWithValidRules);
                checkJson["policy_id"] = policyId;
                policiesAndChecks["checks"].push_back(checkJson);
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
void PolicyParser::ReplaceVariablesInNode(YamlNode& currentNode)
{
    if (currentNode.IsScalar())
    {
        auto value = currentNode.AsString();
        for (const auto& pair : m_variablesMap)
        {
            size_t pos = 0;
            while ((pos = value.find(pair.first, pos)) != std::string::npos)
            {
                value.replace(pos, pair.first.length(), pair.second);
                pos += pair.second.length();
            }
        }
        currentNode.SetScalarValue(value);
    }
    else if (currentNode.IsMap())
    {
        for (auto& [key, node] : currentNode.AsMap())
        {
            ReplaceVariablesInNode(node);
        }
    }
    else if (currentNode.IsSequence())
    {
        auto items = currentNode.AsSequence();
        for (auto& item : items)
        {
            ReplaceVariablesInNode(item);
        }
    }
}
