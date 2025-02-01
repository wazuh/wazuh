/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * March 11, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _RESPONSE_BUILDER_HPP
#define _RESPONSE_BUILDER_HPP

#include "base/logging.hpp"
#include "base/utils/chainOfResponsability.hpp"
#include "base/utils/numericUtils.hpp"
#include "base/utils/stringUtils.hpp"
#include "base/utils/timeUtils.hpp"
#include "databaseFeedManager.hpp"
#include "descriptionsHelper.hpp"
#include "fieldAlertHelper.hpp"
#include "scanContext.hpp"

/**
 * @brief TResponseBuilder class.
 * This class is responsible for building the response details for the vulnerabilities detections.
 * It receives the scan context and the database feed manager and returns the scan context with the event details.
 * Its neccessary to have the context->m_elements populated with the cve detected.
 * Its also necessary to have the context->m_matchConditions populated with the cve and the condition.
 * The condition can be "LessThanOrEqual", "LessThan", "DefaultStatus" or "Equal".
 *
 * @tparam TDatabaseFeedManager database feed manager type.
 * @tparam TScanContext scan context type.
 */
template<typename TDatabaseFeedManager = DatabaseFeedManager, typename TScanContext = ScanContext>
class TResponseBuilder final : public utils::patterns::AbstractHandler<std::shared_ptr<TScanContext>>
{
private:
    std::shared_ptr<TDatabaseFeedManager> m_databaseFeedManager;

    void buildUnderEvaluation(nlohmann::json& json, CveDescription description)
    {
        json["under_evaluation"] = base::utils::numeric::floatToDoubleRound(description.scoreBase, 2) == 0
                                   || description.classification.empty() || description.severity.empty();
    }

    void buildScore(const std::string& cveId, nlohmann::json& json, CveDescription description)
    {
        const auto cvssVersion {description.scoreVersion};
        const auto scoreVersion {std::string("cvss") + cvssVersion.front()};

        if (!cvssVersion.empty())
        {
            nlohmann::json vectorObj;
            if (scoreVersion.compare("cvss2") == 0)
            {
                vectorObj["access_complexity"] = description.accessComplexity;
                vectorObj["authentication"] = description.authentication;
            }
            else if (scoreVersion.compare("cvss3") == 0)
            {
                vectorObj["attack_vector"] = description.attackVector;
                vectorObj["privileges_required"] = description.privilegesRequired;
                vectorObj["scope"] = description.scope;
                vectorObj["user_interaction"] = description.userInteraction;
            }
            else
            {
                LOG_DEBUG("CVSS version not supported: {}", cvssVersion);
            }

            vectorObj["availability"] = description.availabilityImpact;
            vectorObj["confidentiality_impact"] = description.confidentialityImpact;
            vectorObj["integrity_impact"] = description.integrityImpact;

            json["cvss"][scoreVersion]["vector"] = std::move(vectorObj);
        }
        else
        {
            LOG_DEBUG("CVSS version not found for CVE: {}", cveId);
        }
    }

    void buildMatchCondition(nlohmann::json& json, const MatchCondition& condition)
    {
        if (condition.condition == MatchRuleCondition::LessThanOrEqual)
        {
            json["condition"] = "Package less than or equal to " + condition.version;
        }
        else if (condition.condition == MatchRuleCondition::LessThan)
        {
            json["condition"] = "Package less than " + condition.version;
        }
        else if (condition.condition == MatchRuleCondition::DefaultStatus)
        {
            json["condition"] = "Package default status";
        }
        else if (condition.condition == MatchRuleCondition::Equal)
        {
            json["condition"] = "Package equal to " + condition.version;
        }
        else
        {
            // If we have a match condition, the condition should be one of the above, and this is an error.
            throw std::range_error("Invalid condition: " + std::to_string(static_cast<int>(condition.condition)));
        }
    }

public:
    // LCOV_EXCL_START
    /**
     * @brief ResponseBuilder constructor.
     *
     * @param databaseFeedManager Database feed manager.
     */
    explicit TResponseBuilder(std::shared_ptr<TDatabaseFeedManager>& databaseFeedManager)
        : m_databaseFeedManager(databaseFeedManager)
    {
    }

    /**
     * @brief Class destructor.
     *
     */
    ~TResponseBuilder() = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Scan context.
     * @return std::shared_ptr<ScanContext> Abstract handler.
     */
    std::shared_ptr<TScanContext> handleRequest(std::shared_ptr<ScanContext> data) override
    {
        LOG_DEBUG("Building event details for component type: {}", static_cast<int>(data->scannerType()));

        // If we dont have elements, we dont have to build the response details, no detections.
        if (data->m_elements.empty())
        {
            return utils::patterns::AbstractHandler<std::shared_ptr<TScanContext>>::handleRequest(std::move(data));
        }

        // If the scanner type is package, we need to check if the package item id is empty, because is the key to get
        // the package information, if we receive an empty package item id, is a request data error.
        if (data->scannerType() == ScannerType::Package && data->packageItemId().empty())
        {
            throw std::invalid_argument("Package item id is empty");
        }

        nlohmann::json dataElements = nlohmann::json::array();

        const auto vulnerabilitySource = m_databaseFeedManager->vendorsMap()
                                             .at("adp_descriptions")
                                             .at(std::get<VulnerabilitySource::ADP_BASE>(data->m_vulnerabilitySource))
                                             .at("adp");

        // For each element, we get the vulnerability descriptive information and build the event details.
        for (auto& [cve, json] : data->m_elements)
        {
            try
            {
                DescriptionsHelper::vulnerabilityDescription(
                    cve,
                    data->m_vulnerabilitySource,
                    m_databaseFeedManager,
                    [&](const CveDescription& description)
                    {
                        switch (data->scannerType())
                        {
                            case ScannerType::Package:
                                json["category"] = "Packages";
                                json["item_id"] = data->packageItemId();
                                break;

                            case ScannerType::Os: json["category"] = "OS"; break;

                            default: throw std::invalid_argument("Invalid scanner type"); break;
                        }

                        // Status date
                        json["classification"] = FieldAlertHelper::fillEmptyOrNegative(description.classification);
                        json["description"] = description.description;
                        json["detected_at"] = base::utils::time::getCurrentISO8601();
                        json["enumeration"] = "CVE";
                        json["id"] = cve;
                        json["published_at"] = description.datePublished;
                        json["reference"] = description.reference;
                        json["score"]["base"] = FieldAlertHelper::fillEmptyOrNegative(
                            base::utils::numeric::floatToDoubleRound(description.scoreBase, 2));
                        json["score"]["version"] = FieldAlertHelper::fillEmptyOrNegative(description.scoreVersion);
                        json["severity"] = FieldAlertHelper::fillEmptyOrNegative(base::utils::string::toSentenceCase(
                            std::string(description.severity.data(), description.severity.size())));
                        json["source"] = vulnerabilitySource;

                        // Alert data
                        json["assigner"] = description.assignerShortName;
                        json["cwe_reference"] = description.cweId;
                        json["updated"] = description.dateUpdated;

                        if (const auto it = data->m_matchConditions.find(cve); it != data->m_matchConditions.end())
                        {
                            buildMatchCondition(json, it->second);
                        }
                        else
                        {
                            // If we dont have a match condition, we dont have a CVE match, and this is an error.
                            throw std::invalid_argument("Match condition not found for CVE: " + cve);
                        }

                        buildScore(cve, json, description);
                        buildUnderEvaluation(json, description);

                        data->moveResponseData(json);
                    });
            }
            catch (const std::exception& e)
            {
                LOG_ERROR("Error building event details for CVE: {}. Error message: {}", cve, e.what());
            }
        }

        return utils::patterns::AbstractHandler<std::shared_ptr<TScanContext>>::handleRequest(std::move(data));
    }
};

using ResponseBuilder = TResponseBuilder<>;

#endif // _RESPONSE_BUILDER_HPP
