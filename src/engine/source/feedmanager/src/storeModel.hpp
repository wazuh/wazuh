/*
 * Wazuh Vulnerability scanner - Database Feed Manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _STORE_MODEL_HPP
#define _STORE_MODEL_HPP

#include "base/utils/chainOfResponsability.hpp"
#include "eventContext.hpp"
#include "updateCVECandidates.hpp"
#include "updateCVEDescription.hpp"
#include "updateCVERemediations.hpp"
#include "updateHotfixes.hpp"

/**
 * @brief StoreModel class.
 *
 */
class StoreModel final : public utils::patterns::AbstractHandler<std::shared_ptr<EventContext>>
{
public:
    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Scan context.
     * @return std::shared_ptr<ScanContext> Abstract handler.
     */
    std::shared_ptr<EventContext> handleRequest(std::shared_ptr<EventContext> data) override
    {
        if (data->resourceType == ResourceType::CVE)
        {
            if (!data->cve5Buffer.data())
            {
                throw std::runtime_error("CVE5 buffer is empty"); // LCOV_EXCL_LINE
            }
            auto cve5Entry = cve_v5::GetEntry(data->cve5Buffer.data());
            const auto& type = data->resource.contains("type") ? data->resource.at("type").get<std::string>() : "";
            std::string state;

            if (cve5Entry->cveMetadata() && cve5Entry->cveMetadata()->state())
            {
                state = cve5Entry->cveMetadata()->state()->str();
            }

            if ("update" == type)
            {
                // We clean the candidates DBs to keep the data synced
                if ("PUBLISHED" == state)
                {
                    UpdateHotfixes::storeVulnerabilityHotfixes(cve5Entry, data->feedDatabase);
                    UpdateCVERemediations::storeVulnerabilityRemediation(cve5Entry, data->feedDatabase);
                    UpdateCVEDescription::storeVulnerabilityDescription(cve5Entry, data->feedDatabase);
                    UpdateCVECandidates::storeVulnerabilityCandidate(cve5Entry, data->feedDatabase);
                }
                else if ("REJECTED" == state)
                {
                    UpdateHotfixes::removeHotfix(cve5Entry, data->feedDatabase);
                    UpdateCVERemediations::removeRemediation(cve5Entry, data->feedDatabase);
                    UpdateCVEDescription::removeVulnerabilityDescription(cve5Entry, data->feedDatabase);
                    UpdateCVECandidates::removeVulnerabilityCandidate(cve5Entry, data->feedDatabase);
                }
                else
                {
                    throw std::runtime_error("Invalid state of resource.");
                }
            }
            else if ("create" == type)
            {
                if ("PUBLISHED" == state)
                {
                    UpdateHotfixes::storeVulnerabilityHotfixes(cve5Entry, data->feedDatabase);
                    UpdateCVERemediations::storeVulnerabilityRemediation(cve5Entry, data->feedDatabase);
                    UpdateCVEDescription::storeVulnerabilityDescription(cve5Entry, data->feedDatabase);
                    UpdateCVECandidates::storeVulnerabilityCandidate(cve5Entry, data->feedDatabase);
                }
            }
            else
            {
                throw std::runtime_error("Invalid type of resource.");
            }
        }

        return AbstractHandler<std::shared_ptr<EventContext>>::handleRequest(std::move(data));
    }
};

#endif // _STORE_MODEL_HPP
