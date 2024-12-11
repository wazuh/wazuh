/*
 * Wazuh Vulnerability scanner - Database Feed Manager
 * Copyright (C) 2015, Wazuh Inc.
 * Oct 6, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPDATE_CVE_CANDIDATES_HPP
#define _UPDATE_CVE_CANDIDATES_HPP

#include "base/utils/rocksDBWrapper.hpp"
#include "base/utils/stringUtils.hpp"
#include "cve5_generated.h"
#include "vulnerabilityCandidate_generated.h"

const std::unordered_map<std::string, NSVulnerabilityScanner::Status> VERSION_STATUS_MAP {
    {"unaffected", NSVulnerabilityScanner::Status::Status_unaffected},
    {"affected", NSVulnerabilityScanner::Status::Status_affected},
    {"unknown", NSVulnerabilityScanner::Status::Status_unknown}};

const std::string CVE_PACKAGE_COLUMN_NAME_PREFIX {"cve_package"};

/**
 * @brief UpdateCVECandidates class.
 *
 */
class UpdateCVECandidates final
{
public:
    /**
     * @brief Inserts the candidate data into the corresponding database.
     *
     * @param cve5Flatbuffer CVE5 Flatbuffer.
     * @param feedDatabase rocksDB wrapper instance.
     */
    static void storeVulnerabilityCandidate(const cve_v5::Entry* cve5Flatbuffer,
                                            utils::rocksdb::IRocksDBWrapper* feedDatabase)
    {
        if (!cve5Flatbuffer || !cve5Flatbuffer->containers())
        {
            return;
        }

        const auto cveId {cve5Flatbuffer->cveMetadata()->cveId()};

        if (!cveId)
        {
            throw std::runtime_error("Empty cveId.");
        }

        auto createPackageColumnName = [](std::string_view shortName)
        {
            std::string cvePackageColumnName;
            cvePackageColumnName.reserve(CVE_PACKAGE_COLUMN_NAME_PREFIX.size() + 1 + shortName.size());

            cvePackageColumnName += CVE_PACKAGE_COLUMN_NAME_PREFIX;
            cvePackageColumnName += "_";
            cvePackageColumnName += shortName;

            return cvePackageColumnName;
        };

        auto candidateLambda = [&](const flatbuffers::Vector<::flatbuffers::Offset<cve_v5::Affected>>* affectedVector,
                                   const std::string& shortName)
        {
            std::unordered_map<
                std::string,
                std::pair<std::vector<flatbuffers::Offset<NSVulnerabilityScanner::ScanVulnerabilityCandidate>>,
                          flatbuffers::FlatBufferBuilder>>
                candidatesArraysMap;

            for (const auto& affected : *affectedVector)
            {
                if (!affected->product())
                {
                    continue;
                }

                const auto productName = base::utils::string::toLowerCase(affected->product()->str());
                if (candidatesArraysMap.find(productName) == candidatesArraysMap.end())
                {
                    candidatesArraysMap.emplace(
                        productName,
                        std::pair<std::vector<flatbuffers::Offset<NSVulnerabilityScanner::ScanVulnerabilityCandidate>>,
                                  flatbuffers::FlatBufferBuilder>());
                }

                auto& candidateBuilderRef = candidatesArraysMap.at(productName).second;

                // Versions array
                std::vector<flatbuffers::Offset<NSVulnerabilityScanner::Version>> versionFBArray;
                if (affected->versions())
                {
                    for (const auto& versionElement : *affected->versions())
                    {
                        NSVulnerabilityScanner::Status status = NSVulnerabilityScanner::Status::Status_unknown;

                        if (versionElement->status()
                            && VERSION_STATUS_MAP.find(versionElement->status()->str()) != VERSION_STATUS_MAP.end())
                        {
                            status = VERSION_STATUS_MAP.at(versionElement->status()->str());
                        }

                        auto versionFB = NSVulnerabilityScanner::CreateVersionDirect(
                            candidateBuilderRef,
                            status,
                            versionElement->version() ? versionElement->version()->c_str() : nullptr,
                            versionElement->lessThan() ? versionElement->lessThan()->c_str() : nullptr,
                            versionElement->lessThanOrEqual() ? versionElement->lessThanOrEqual()->c_str() : nullptr,
                            versionElement->versionType() ? versionElement->versionType()->c_str() : nullptr);

                        versionFBArray.push_back(versionFB);
                    }
                }

                // Platforms array
                std::vector<flatbuffers::Offset<flatbuffers::String>> platformsVec;
                if (affected->platforms())
                {
                    for (const auto& platform : *affected->platforms())
                    {
                        platformsVec.push_back(candidateBuilderRef.CreateString(platform->str()));
                    }
                }

                NSVulnerabilityScanner::Status defaultStatus = NSVulnerabilityScanner::Status::Status_unknown;

                if (affected->defaultStatus()
                    && VERSION_STATUS_MAP.find(affected->defaultStatus()->str()) != VERSION_STATUS_MAP.end())
                {
                    defaultStatus = VERSION_STATUS_MAP.at(affected->defaultStatus()->str());
                }

                // The vendor field will only be stored for the NVD
                auto candidate = NSVulnerabilityScanner::CreateScanVulnerabilityCandidateDirect(
                    candidateBuilderRef,
                    cveId->c_str(),
                    defaultStatus,
                    affected->platforms() && affected->platforms()->size() ? &platformsVec : nullptr,
                    &versionFBArray,
                    affected->vendor() && shortName == "nvd" ? affected->vendor()->c_str() : nullptr);

                candidatesArraysMap.at(productName).first.push_back(candidate);
            }

            const auto CVE_PACKAGE_COLUMN_NAME = createPackageColumnName(shortName);

            // Get all candidates stored in the database.
            // If some of the candidates are already store, and is removed in the new feed, we need to remove it from
            // the database.
            const auto cveIdKey = cveId->str() + "_";
            std::vector<std::pair<std::string, std::string>> previousCandidates;

            for (const auto& [cvePackage, packageCve] : feedDatabase->seek(cveIdKey, CVE_PACKAGE_COLUMN_NAME))
            {
                previousCandidates.emplace_back(packageCve.ToString(), cvePackage);
            }

            for (const auto& [packageCve, cvePackage] : previousCandidates)
            {
                // Remove _CVE-XXXX-XXXX from the key.
                auto packageCandidate = packageCve;
                base::utils::string::replaceFirst(packageCandidate, std::string("_" + cveId->str()), "");

                if (candidatesArraysMap.find(packageCandidate) == candidatesArraysMap.end())
                {
                    feedDatabase->delete_(packageCve, shortName);
                    feedDatabase->delete_(cvePackage, CVE_PACKAGE_COLUMN_NAME);
                }
            }

            for (auto& [key, value] : candidatesArraysMap)
            {
                const auto finalArray =
                    NSVulnerabilityScanner::CreateScanVulnerabilityCandidateArrayDirect(value.second, &value.first);
                value.second.Finish(finalArray);

                const auto buffer = value.second.GetBufferPointer();
                const auto flatbufferSize = value.second.GetSize();

                const rocksdb::Slice slice(reinterpret_cast<const char*>(buffer), flatbufferSize);
                const auto finalKey = key + "_" + cveId->str();
                const auto reverseKey = cveId->str() + "_" + key;

                if (rocksdb::PinnableSlice currentValueCandidate;
                    !feedDatabase->get(finalKey, currentValueCandidate, shortName)
                    || currentValueCandidate.size() != slice.size()
                    || std::memcmp(currentValueCandidate.data(), slice.data(), slice.size()) != 0)
                {
                    feedDatabase->put(finalKey, slice, shortName);
                    feedDatabase->put(reverseKey, finalKey, CVE_PACKAGE_COLUMN_NAME);
                }
            }
        };

        if (cve5Flatbuffer->containers()->adp())
        {
            for (const auto& adp : *cve5Flatbuffer->containers()->adp())
            {
                if (!adp->providerMetadata() || !adp->providerMetadata()->x_subShortName() || !adp->affected())
                {
                    continue;
                }

                const auto shortName = adp->providerMetadata()->x_subShortName()->str();

                if (!feedDatabase->columnExists(shortName))
                {
                    feedDatabase->createColumn(shortName);
                }

                // Create column to maintain the relationship between the cve and the package.
                if (const auto CVE_PACKAGE_COLUMN_NAME = createPackageColumnName(shortName);
                    !feedDatabase->columnExists(CVE_PACKAGE_COLUMN_NAME))
                {
                    feedDatabase->createColumn(CVE_PACKAGE_COLUMN_NAME);
                }

                candidateLambda(adp->affected(), shortName);
            }
        }

        if (cve5Flatbuffer->containers()->cna())
        {
            auto cna = cve5Flatbuffer->containers()->cna();

            if (!cna->affected())
            {
                return;
            }

            if (!cna->providerMetadata() || !cna->providerMetadata()->shortName())
            {
                return;
            }

            const auto shortName = cna->providerMetadata()->shortName()->str();

            if (!feedDatabase->columnExists(shortName))
            {
                feedDatabase->createColumn(shortName);
            }

            // Create column to maintain the relationship between the cve and the package.
            if (const auto CVE_PACKAGE_COLUMN_NAME = createPackageColumnName(shortName);
                !feedDatabase->columnExists(CVE_PACKAGE_COLUMN_NAME))
            {
                feedDatabase->createColumn(CVE_PACKAGE_COLUMN_NAME);
            }

            candidateLambda(cna->affected(), shortName);
        }
    }

    /**
     * @brief Deletes all the candidates related to a CVE from the feed DB.
     *
     * @param cve5Flatbuffer Flatbuffer object containing the CVE information.
     * @param feedDatabase rocksDB wrapper instance.
     */
    static void removeVulnerabilityCandidate(const cve_v5::Entry* cve5Flatbuffer,
                                             utils::rocksdb::IRocksDBWrapper* feedDatabase)
    {
        if (!cve5Flatbuffer->cveMetadata() || !cve5Flatbuffer->cveMetadata()->cveId())
        {
            return;
        }

        auto createPackageColumnName = [](std::string_view shortName)
        {
            std::string cvePackageColumnName;
            cvePackageColumnName.reserve(CVE_PACKAGE_COLUMN_NAME_PREFIX.size() + 1 + shortName.size());

            cvePackageColumnName += CVE_PACKAGE_COLUMN_NAME_PREFIX;
            cvePackageColumnName += "_";
            cvePackageColumnName += shortName;

            return cvePackageColumnName;
        };

        const auto cveId = cve5Flatbuffer->cveMetadata()->cveId()->str() + "_";

        const auto cnaNames = feedDatabase->getAllColumns();

        for (const auto& cnaName : cnaNames)
        {
            const auto CVE_PACKAGE_COLUMN_NAME = createPackageColumnName(cnaName);

            if (feedDatabase->columnExists(CVE_PACKAGE_COLUMN_NAME))
            {
                // Delete elements inner iteration is unsafe.
                std::vector<std::string> cvePackagesToDelete;
                for (const auto& [cvePackage, packageCve] : feedDatabase->seek(cveId, CVE_PACKAGE_COLUMN_NAME))
                {
                    feedDatabase->delete_(packageCve.ToString(), cnaName);
                    cvePackagesToDelete.push_back(cvePackage);
                }

                for (const auto& cvePackage : cvePackagesToDelete)
                {
                    feedDatabase->delete_(cvePackage, CVE_PACKAGE_COLUMN_NAME);
                }
            }
        }
    }
};

#endif // _UPDATE_CVE_CANDIDATES_HPP
