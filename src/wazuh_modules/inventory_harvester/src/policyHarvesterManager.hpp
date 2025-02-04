/*
 * Wazuh vulnerability scanner - Policy Manager
 * Copyright (C) 2015, Wazuh Inc.
 * January 22, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _POLICY_HARVESTER_MANAGER_HPP
#define _POLICY_HARVESTER_MANAGER_HPP

#include "loggerHelper.h"
#include "singleton.hpp"
#include "stringHelper.h"
#include <json.hpp>
#include <string>

constexpr auto UNKNOWN_VALUE {" "};
constexpr auto STATES_INDEX_NAME_PREFIX {"wazuh-states-"};

/**
 * @brief PolicyHarvesterManager class.
 *
 */
class PolicyHarvesterManager final : public Singleton<PolicyHarvesterManager>
{
private:
    nlohmann::json m_configuration;

    /**
     * @brief Set the default policy.
     * This method is used to set the default policy, if the policy is not set in the input configuration.
     *
     * @param configuration The configuration to set the default policy.
     *
     * @return The configuration merged with the default policy.
     */
    nlohmann::json setDefaultPolicy(const nlohmann::json& configuration) const
    {
        nlohmann::json newPolicy = configuration;
        // Set default policy
        if (newPolicy.contains("indexer"))
        {
            if (!newPolicy.at("indexer").contains("hosts"))
            {
                newPolicy["indexer"]["hosts"] = nlohmann::json::array();
                newPolicy["indexer"]["hosts"].push_back("http://localhost:9200");
            }

            if (!newPolicy.at("indexer").contains("username"))
            {
                newPolicy["indexer"]["username"] = "";
            }

            if (!newPolicy.at("indexer").contains("password"))
            {
                newPolicy["indexer"]["password"] = "";
            }

            if (!newPolicy.at("indexer").contains("ssl"))
            {
                newPolicy["indexer"]["ssl"] = nlohmann::json::object();
                newPolicy["indexer"]["ssl"]["certificate_authorities"] = nlohmann::json::array();
                newPolicy["indexer"]["ssl"]["certificate"] = "";
                newPolicy["indexer"]["ssl"]["key"] = "";
            }
            else
            {
                if (!newPolicy.at("indexer").at("ssl").contains("certificate_authorities"))
                {
                    newPolicy["indexer"]["ssl"]["certificate_authorities"] = nlohmann::json::array();
                }

                if (!newPolicy.at("indexer").at("ssl").contains("certificate"))
                {
                    newPolicy["indexer"]["ssl"]["certificate"] = "";
                }

                if (!newPolicy.at("indexer").at("ssl").contains("key"))
                {
                    newPolicy["indexer"]["ssl"]["key"] = "";
                }
            }
        }
        else
        {
            newPolicy["indexer"] = nlohmann::json::object();
            newPolicy["indexer"]["enabled"] = "no";
            newPolicy["indexer"]["hosts"] = nlohmann::json::array();
            newPolicy["indexer"]["username"] = "";
            newPolicy["indexer"]["password"] = "";
            newPolicy["indexer"]["ssl"] = nlohmann::json::object();
            newPolicy["indexer"]["ssl"]["certificate_authorities"] = nlohmann::json::array();
            newPolicy["indexer"]["ssl"]["certificate"] = "";
            newPolicy["indexer"]["ssl"]["key"] = "";
        }

        if (!newPolicy.contains("managerDisabledScan"))
        {
            newPolicy["managerDisabledScan"] = false;
        }

        if (!newPolicy.contains("clusterNodeName"))
        {
            newPolicy["clusterNodeName"] = UNKNOWN_VALUE;
        }

        if (!newPolicy.contains("clusterName"))
        {
            newPolicy["clusterName"] = UNKNOWN_VALUE;
        }

        return newPolicy;
    }

    /**
     * @brief Validates and configures the indexer based on the provided JSON object.
     *
     * This function takes a JSON object as input, which is expected to contain configuration
     * information. It validates the JSON object to ensure it contains the required fields and has valid values,
     * based on the previous configuration of the vulnerability detection.
     * If the validation passes, no exception is thrown.
     *
     * @param configuration A constant reference to a JSON object representing the complete configuration.
     *
     * @note This function assumes that the provided JSON object follows a specific format.
     * @note If validation fails, this function throws std::runtime exception.
     */
    void validateIndexerConfiguration(const nlohmann::json& configuration) const
    {
        if (!configuration.at("indexer").contains("enabled"))
        {
            throw std::runtime_error("Missing enabled field.");
        }
    }

    /**
     * @brief Validates and configures the configuration with the provided JSON object.
     * This function takes a JSON object as input, which is expected to contain configuration.
     *
     * @param configuration A constant reference to a JSON object with the configuration.
     */
    void validateAndLoadConfiguration(const nlohmann::json& configuration)
    {
        // Validate JSON
        validateConfiguration(configuration);

        // Reset configuration
        loadConfiguration(setDefaultPolicy(configuration));
    }

    /**
     * @brief Loads configuration settings from a JSON object.
     *
     * This function takes a JSON object containing configuration settings and
     * processes them for use by the policy manager's module.
     *
     * @param configuration The JSON object containing configuration settings.
     */
    void loadConfiguration(const nlohmann::json& configuration)
    {
        m_configuration = configuration;
    }

public:
    /**
     * @brief Initializes manager.
     *
     * @param configuration Manager configuration.
     */
    // LCOV_EXCL_START
    void initialize(const nlohmann::json& configuration)
    {
        logDebug2(LOGGER_DEFAULT_TAG, "Initializing PolicyHarvesterManager.");
        // Load and validate configuration
        validateAndLoadConfiguration(configuration);
    }
    // LCOV_EXCL_STOP

    /**
     * @brief Teardown manager.
     *
     * @details This function is called when the manager is being destroyed.
     */
    void teardown() {}

    /**
     * @brief Validates the configuration settings of the vulnerability-detection's module.
     *
     * @param configuration A constant reference to a JSON object with the configuration.
     *
     * This function checks if the configuration settings are valid and conform
     * to the expected format and values.
     *
     */

    void validateConfiguration(const nlohmann::json& configuration) const
    {
        // If the "indexer" configuration exists, validate it.
        // Otherwise, since it is not mandatory, the default policy will be used.
        if (configuration.contains("indexer"))
        {
            validateIndexerConfiguration(configuration);
        }
    }

    /**
     * @brief Get indexer connector configuration.
     *
     * @return nlohmann::json Connector configuration.
     */
    const nlohmann::json& getIndexerConfiguration() const
    {
        return m_configuration.at("indexer");
    }

    /**
     * @brief Get indexer status.
     *
     * @return true if enabled or false if not.
     */
    bool isIndexerEnabled() const
    {
        return Utils::parseStrToBool(m_configuration.at("indexer").at("enabled"));
    }

    /**
     * @brief Retrieves the current status of the manager's scan.
     *
     * This function retrieves the current status of the manager's scan
     * from the configuration and returns it as a ManagerScanStatus enum value.
     *
     * @return true if the manager's scan is disabled, false otherwise.
     */
    bool getManagerDisabledScan() const
    {
        return m_configuration.at("managerDisabledScan").get<bool>() == true;
    }

    /**
     * @brief Retrieves the name of the manager node for vulnerability detection.
     *
     * This function retrieves the name of the manager node for vulnerability detection
     * from the configuration and returns it as a std::string.
     *
     * @return std::string The name of the manager node for vulnerability detection.
     */
    std::string_view getClusterNodeName() const
    {
        return m_configuration.at("clusterNodeName").get<std::string_view>();
    }

    /**
     * @brief Get status of the cluster.
     * This function retrieves the cluster status from the configuration and returns it as a bool
     * @return bool cluster status.
     */
    bool getClusterStatus() const
    {
        return m_configuration.at("clusterEnabled").get<bool>();
    }

    /**
     * @brief Get cluster name.
     * This function retrieves the cluster name from the configuration and returns it as a std::string
     * @return std::string cluster name.
     */
    std::string_view getClusterName() const
    {
        return m_configuration.at("clusterName").get<std::string_view>();
    }

    nlohmann::json buildIndexerConfig(const std::string& name) const
    {
        auto config = PolicyHarvesterManager::instance().getIndexerConfiguration();
        auto clusterName = Utils::toLowerCaseView(PolicyHarvesterManager::instance().getClusterName());
        config["name"] = std::string(STATES_INDEX_NAME_PREFIX) + name + "-" + clusterName;
        return config;
    }

    std::string buildIndexerTemplatePath(const std::string& name) const
    {
        if (!m_configuration.at("indexer").contains("template_path"))
        {
            return "templates/" + name + "_states_template.json";
        }
        else
        {
            return m_configuration.at("indexer").at("template_path").get_ref<const std::string&>();
        }
    }

    std::string buildIndexerUpdateTemplatePath(const std::string& name) const
    {
        if (!m_configuration.at("indexer").contains("update_template_path"))
        {
            return "templates/" + name + "_states_update_mappings.json";
        }
        else
        {
            return m_configuration.at("indexer").at("update_template_path").get_ref<const std::string&>();
        }
    }
};

#endif //_POLICY_HARVESTER_MANAGER_HPP
