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
    std::shared_ptr<TScanContext> handleRequest(std::shared_ptr<TScanContext> data) override
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

        // For each element, we get the vulnerability descriptive information and build the event details.
        for (auto& [cve, json] : data->m_elements)
        {
            FlatbufferDataPair<NSVulnerabilityScanner::VulnerabilityDescription> returnData;
            m_databaseFeedManager->getVulnerabiltyDescriptiveInformation(cve, returnData);
            if (returnData.data)
            {
                switch (data->scannerType())
                {
                    case ScannerType::Package:
                        json["wcs"]["category"] = "Packages";
                        json["wcs"]["item_id"] = data->packageItemId();
                        break;

                    case ScannerType::Os: json["wcs"]["category"] = "OS"; break;

                    default: throw std::invalid_argument("Invalid scanner type"); break;
                }

                // Status date
                json["wcs"]["classification"] = returnData.data->classification()->str();
                json["wcs"]["description"] = returnData.data->description()->str();
                json["wcs"]["detected_at"] = base::utils::time::getCurrentISO8601();
                json["wcs"]["enumeration"] = "CVE";
                json["wcs"]["id"] = cve;
                json["wcs"]["published_at"] = returnData.data->datePublished()->str();
                json["wcs"]["reference"] = returnData.data->reference()->str();
                json["wcs"]["scanner"]["vendor"] = "Wazuh";
                json["wcs"]["score"]["base"] =
                    base::utils::numeric::floatToDoubleRound(returnData.data->scoreBase(), 2);
                json["wcs"]["score"]["version"] = returnData.data->scoreVersion()->str();
                json["wcs"]["severity"] = base::utils::string::toSentenceCase(returnData.data->severity()->str());

                // Alert data
                json["alert"]["assigner"] = returnData.data->assignerShortName()->str();
                json["alert"]["cwe_reference"] = returnData.data->cweId()->str();
                json["alert"]["rationale"] = returnData.data->description()->str();
                json["alert"]["updated"] = returnData.data->dateUpdated()->str();

                if (const auto it = data->m_matchConditions.find(cve); it != data->m_matchConditions.end())
                {
                    if (it->second.condition == MatchRuleCondition::LessThanOrEqual)
                    {
                        json["alert"]["condition"] = "Package less than or equal to " + it->second.version;
                    }
                    else if (it->second.condition == MatchRuleCondition::LessThan)
                    {
                        json["alert"]["condition"] = "Package less than " + it->second.version;
                    }
                    else if (it->second.condition == MatchRuleCondition::DefaultStatus)
                    {
                        json["alert"]["condition"] = "Package default status";
                    }
                    else if (it->second.condition == MatchRuleCondition::Equal)
                    {
                        json["alert"]["condition"] = "Package equal to " + it->second.version;
                    }
                    else
                    {
                        // If we have a match condition, the condition should be one of the above, and this is an error.
                        throw std::range_error("Invalid condition: "
                                               + std::to_string(static_cast<int>(it->second.condition)));
                    }
                }
                else
                {
                    // If we dont have a match condition, we dont have a CVE match, and this is an error.
                    throw std::invalid_argument("Match condition not found for CVE: " + cve);
                }

                const auto cvssVersion {returnData.data->scoreVersion()->str()};
                const auto scoreVersion {"cvss" + cvssVersion.substr(0, 1)};

                if (!cvssVersion.empty())
                {
                    nlohmann::json vectorObj;
                    if (scoreVersion.compare("cvss2") == 0)
                    {
                        vectorObj["access_complexity"] = returnData.data->accessComplexity()->str();
                        vectorObj["authentication"] = returnData.data->authentication()->str();
                    }
                    else if (scoreVersion.compare("cvss3") == 0)
                    {
                        vectorObj["attack_vector"] = returnData.data->attackVector()->str();
                        vectorObj["privileges_required"] = returnData.data->privilegesRequired()->str();
                        vectorObj["scope"] = returnData.data->scope()->str();
                        vectorObj["user_interaction"] = returnData.data->userInteraction()->str();
                    }
                    else
                    {
                        LOG_DEBUG("CVSS version not supported: {}", cvssVersion);
                    }

                    vectorObj["availability"] = returnData.data->availabilityImpact()->str();
                    vectorObj["confidentiality_impact"] = returnData.data->confidentialityImpact()->str();
                    vectorObj["integrity_impact"] = returnData.data->integrityImpact()->str();

                    json["alert"]["cvss"][scoreVersion]["vector"] = std::move(vectorObj);
                }
                else
                {
                    LOG_DEBUG("CVSS version not found for CVE: {}", cve);
                }

                dataElements.push_back(std::move(json));
            }
        }

        data->moveResponseData(dataElements);

        return utils::patterns::AbstractHandler<std::shared_ptr<TScanContext>>::handleRequest(std::move(data));
    }
};

using ResponseBuilder = TResponseBuilder<>;

#endif // _RESPONSE_BUILDER_HPP
