/*
 * Wazuh Vulnerability scanner - Database Feed Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Oct 3, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPDATE_CVE_DESCRIPTION_HPP
#define _UPDATE_CVE_DESCRIPTION_HPP

#include "base/utils/rocksDBWrapper.hpp"
#include "cve5_generated.h"
#include "vulnerabilityDescription_generated.h"

constexpr auto DESCRIPTIONS_COLUMN {"descriptions"};
/**
 * @brief UpdateCVEDescription class.
 *
 */
class UpdateCVEDescription final
{
public:
    /**
     * @brief Reads CVE5 database, creates a vulnerability description flatbuffer and stores it in a specific RocksDB
     * database.
     *
     * @param cve5Flatbuffer CVE5 Flatbuffer.
     * @param feedDatabase rocksDB wrapper instance.
     */
    static void storeVulnerabilityDescription(const cve_v5::Entry* cve5Flatbuffer,
                                              utils::rocksdb::IRocksDBWrapper* feedDatabase)
    {
        if (cve5Flatbuffer->containers() && cve5Flatbuffer->containers()->cna())
        {
            auto cna = cve5Flatbuffer->containers()->cna();
            // Missing metrics object is valid in a CVE5 schema.
            auto metricsArray = cna->metrics();
            auto descriptionArray = cna->descriptions();
            auto referencesArray = cna->references();
            auto problemTypesArray = cna->problemTypes();
            auto cve5Metadata = cve5Flatbuffer->cveMetadata();

            float vulnDescFBScoreBase = 0.0;
            std::string vulnDescFBClassificationStr;
            std::string vulnDescFBDescriptionStr;
            std::string vulnDescFBSeverityStr;
            std::string vulnDescFBScoreVersionStr;
            std::string vulnDescFBReferenceStr;
            std::string vulnDescFBAssignerStr;
            std::string vulnDescFBCWEIdStr;
            std::string vulnDescFBDataPublishedStr;
            std::string vulnDescFBDataUpdatedStr;
            std::string vulnDescFBAccessComplexityStr;
            std::string vulnDescFBAttackVectorStr;
            std::string vulnDescFBAuthenticationStr;
            std::string vulnDescFBAvailabilityStr;
            std::string vulnDescFBConfidentialityImpactStr;
            std::string vulnDescFBIntegrityImpactStr;
            std::string vulnDescFBPrivilegesRequiredStr;
            std::string vulnDescFBScopeStr;
            std::string vulnDescFBUserInteractionStr;

            if (descriptionArray)
            {
                for (const auto& field : *descriptionArray)
                {
                    if (field->lang()->str().compare("en") == 0)
                    {
                        vulnDescFBDescriptionStr = field->value()->str();
                        break;
                    }
                }
            }

            if (referencesArray)
            {
                for (const auto& field : *referencesArray)
                {
                    if (field->url())
                    {
                        vulnDescFBReferenceStr += field->url()->str();
                        vulnDescFBReferenceStr += ", ";
                    }
                }
            }

            vulnDescFBReferenceStr = vulnDescFBReferenceStr.substr(0, vulnDescFBReferenceStr.size() - 2);

            // Empty description or empty URL reference are not CVE5 Compliant.
            if (!(vulnDescFBDescriptionStr.empty() || vulnDescFBReferenceStr.empty()))
            {
                flatbuffers::FlatBufferBuilder builder;

                if (metricsArray)
                {
                    for (const auto& field : *metricsArray)
                    {
                        auto metricCVSSV3_1 = field->cvssV3_1();
                        auto metricCVSSV3_0 = field->cvssV3_0();
                        auto metricCVSSV2_0 = field->cvssV2_0();
                        if (metricCVSSV3_1)
                        {
                            vulnDescFBScoreBase = metricCVSSV3_1->baseScore();
                            vulnDescFBSeverityStr =
                                (metricCVSSV3_1->baseSeverity()) ? metricCVSSV3_1->baseSeverity()->str() : "";
                            vulnDescFBScoreVersionStr =
                                (metricCVSSV3_1->version()) ? metricCVSSV3_1->version()->str() : "";
                            vulnDescFBClassificationStr = (field->format()) ? field->format()->str() : "";
                            vulnDescFBAvailabilityStr = (metricCVSSV3_1->availabilityImpact())
                                                            ? metricCVSSV3_1->availabilityImpact()->str()
                                                            : "";
                            vulnDescFBConfidentialityImpactStr = (metricCVSSV3_1->confidentialityImpact())
                                                                     ? metricCVSSV3_1->confidentialityImpact()->str()
                                                                     : "";
                            vulnDescFBIntegrityImpactStr =
                                (metricCVSSV3_1->integrityImpact()) ? metricCVSSV3_1->integrityImpact()->str() : "";
                            vulnDescFBPrivilegesRequiredStr = (metricCVSSV3_1->privilegesRequired())
                                                                  ? metricCVSSV3_1->privilegesRequired()->str()
                                                                  : "";
                            vulnDescFBScopeStr = (metricCVSSV3_1->scope()) ? metricCVSSV3_1->scope()->str() : "";
                            vulnDescFBUserInteractionStr =
                                (metricCVSSV3_1->userInteraction()) ? metricCVSSV3_1->userInteraction()->str() : "";
                            break;
                        }
                        else if (metricCVSSV3_0)
                        {
                            vulnDescFBScoreBase = metricCVSSV3_0->baseScore();
                            vulnDescFBSeverityStr =
                                (metricCVSSV3_0->baseSeverity()) ? metricCVSSV3_0->baseSeverity()->str() : "";
                            vulnDescFBScoreVersionStr =
                                (metricCVSSV3_0->version()) ? metricCVSSV3_0->version()->str() : "";
                            vulnDescFBClassificationStr = (field->format()) ? field->format()->str() : "";
                            vulnDescFBAttackVectorStr =
                                (metricCVSSV3_0->attackVector()) ? metricCVSSV3_0->attackVector()->str() : "";
                            vulnDescFBAvailabilityStr = (metricCVSSV3_0->availabilityImpact())
                                                            ? metricCVSSV3_0->availabilityImpact()->str()
                                                            : "";
                            vulnDescFBConfidentialityImpactStr = (metricCVSSV3_0->confidentialityImpact())
                                                                     ? metricCVSSV3_0->confidentialityImpact()->str()
                                                                     : "";
                            vulnDescFBIntegrityImpactStr =
                                (metricCVSSV3_0->integrityImpact()) ? metricCVSSV3_0->integrityImpact()->str() : "";
                            vulnDescFBPrivilegesRequiredStr = (metricCVSSV3_0->privilegesRequired())
                                                                  ? metricCVSSV3_0->privilegesRequired()->str()
                                                                  : "";
                            vulnDescFBScopeStr = (metricCVSSV3_0->scope()) ? metricCVSSV3_0->scope()->str() : "";
                            vulnDescFBUserInteractionStr =
                                (metricCVSSV3_0->userInteraction()) ? metricCVSSV3_0->userInteraction()->str() : "";
                            break;
                        }
                        else if (metricCVSSV2_0)
                        {
                            vulnDescFBScoreBase = metricCVSSV2_0->baseScore();
                            vulnDescFBSeverityStr = (vulnDescFBScoreBase < 4.0)   ? "LOW"
                                                    : (vulnDescFBScoreBase < 7.0) ? "MEDIUM"
                                                                                  : "HIGH";
                            vulnDescFBScoreVersionStr =
                                (metricCVSSV2_0->version()) ? metricCVSSV2_0->version()->str() : "";
                            vulnDescFBClassificationStr = (field->format()) ? field->format()->str() : "";
                            vulnDescFBAccessComplexityStr =
                                (metricCVSSV2_0->accessComplexity()) ? metricCVSSV2_0->accessComplexity()->str() : "";
                            vulnDescFBAuthenticationStr =
                                (metricCVSSV2_0->authentication()) ? metricCVSSV2_0->authentication()->str() : "";
                            vulnDescFBAvailabilityStr = (metricCVSSV2_0->availabilityImpact())
                                                            ? metricCVSSV2_0->availabilityImpact()->str()
                                                            : "";
                            vulnDescFBConfidentialityImpactStr = (metricCVSSV2_0->confidentialityImpact())
                                                                     ? metricCVSSV2_0->confidentialityImpact()->str()
                                                                     : "";
                            vulnDescFBIntegrityImpactStr =
                                (metricCVSSV2_0->integrityImpact()) ? metricCVSSV2_0->integrityImpact()->str() : "";
                            break;
                        }
                    }
                }

                if (cve5Metadata)
                {
                    vulnDescFBAssignerStr =
                        (cve5Metadata->assignerShortName()) ? cve5Metadata->assignerShortName()->str() : "";
                    vulnDescFBDataPublishedStr =
                        (cve5Metadata->datePublished()) ? cve5Metadata->datePublished()->str() : "";
                    vulnDescFBDataUpdatedStr = (cve5Metadata->dateUpdated()) ? cve5Metadata->dateUpdated()->str() : "";
                }

                if (problemTypesArray)
                {
                    auto problemTypesDescriptionsArray = problemTypesArray->Get(0);
                    if (problemTypesDescriptionsArray)
                    {
                        auto descriptionsProblemTypesArray = problemTypesDescriptionsArray->descriptions();
                        if (descriptionsProblemTypesArray)
                        {
                            vulnDescFBCWEIdStr = (descriptionsProblemTypesArray->Get(0)->cweId())
                                                     ? descriptionsProblemTypesArray->Get(0)->cweId()->str()
                                                     : "";
                        }
                    }
                }

                auto vulnerabilityDescriptionFB = NSVulnerabilityScanner::CreateVulnerabilityDescriptionDirect(
                    builder,
                    vulnDescFBAccessComplexityStr.c_str(),
                    vulnDescFBAssignerStr.c_str(),
                    vulnDescFBAttackVectorStr.c_str(),
                    vulnDescFBAuthenticationStr.c_str(),
                    vulnDescFBAvailabilityStr.c_str(),
                    vulnDescFBClassificationStr.c_str(),
                    vulnDescFBConfidentialityImpactStr.c_str(),
                    vulnDescFBCWEIdStr.c_str(),
                    vulnDescFBDataPublishedStr.c_str(),
                    vulnDescFBDataUpdatedStr.c_str(),
                    vulnDescFBDescriptionStr.c_str(),
                    vulnDescFBIntegrityImpactStr.c_str(),
                    vulnDescFBPrivilegesRequiredStr.c_str(),
                    vulnDescFBReferenceStr.c_str(),
                    vulnDescFBScopeStr.c_str(),
                    vulnDescFBScoreBase,
                    vulnDescFBScoreVersionStr.c_str(),
                    vulnDescFBSeverityStr.c_str(),
                    vulnDescFBUserInteractionStr.c_str());

                builder.Finish(vulnerabilityDescriptionFB);

                const uint8_t* buffer = builder.GetBufferPointer();
                size_t flatbufferSize = builder.GetSize();

                std::string key {cve5Flatbuffer->cveMetadata()->cveId()->str()};
                const rocksdb::Slice VulnerabilityDescriptionSlice(reinterpret_cast<const char*>(buffer),
                                                                   flatbufferSize);

                if (!feedDatabase->columnExists(DESCRIPTIONS_COLUMN))
                {
                    feedDatabase->createColumn(DESCRIPTIONS_COLUMN);
                }

                feedDatabase->put(key, VulnerabilityDescriptionSlice, DESCRIPTIONS_COLUMN);
            }
        }
    }

    /**
     * @brief Deletes a vulnerability description from the database.
     *
     * @param data Flatbuffer object containing the CVE information.
     * @param feedDatabase rocksDB wrapper instance.
     */
    static void removeVulnerabilityDescription(const cve_v5::Entry* data, utils::rocksdb::IRocksDBWrapper* feedDatabase)
    {
        if (!data->cveMetadata() || !data->cveMetadata()->cveId())
        {
            return;
        }

        if (!feedDatabase->columnExists(DESCRIPTIONS_COLUMN))
        {
            return;
        }

        std::string key {data->cveMetadata()->cveId()->str()};
        feedDatabase->delete_(key, DESCRIPTIONS_COLUMN);
    }
};

#endif // _UPDATE_CVE_DESCRIPTION_HPP
