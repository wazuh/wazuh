/*
 * Wazuh storeRemediationsModel
 * Copyright (C) 2015, Wazuh Inc.
 * October 05, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPDATE_CVE_REMEDIATIONS_HPP
#define _UPDATE_CVE_REMEDIATIONS_HPP

#include "base/logging.hpp"
#include "base/utils/rocksDBWrapper.hpp"
#include "cve5_generated.h"
#include "vulnerabilityRemediations_generated.h"

constexpr auto REMEDIATIONS_COLUMN {"remediations"};
/**
 * @brief UpdateCVERemediations class.
 *
 */
class UpdateCVERemediations final
{
public:
    /**
     * @brief Update Remediation Information in a RocksDB Database
     *
     * This function updates remediation information for a given vulnerability (CVE) in a RocksDB database.
     * It extracts remediation data from a provided FlatBuffers 'Entry' object which is the CVE5 object and stores it in
     * the database.
     * If no remediation data is available or an error occurs during the update process, it provides error messages.
     *
     * @param data Pointer to the 'Entry' object containing vulnerability and remediation information.
     * @param feedDatabase Pointer to the 'RocksDB' object for interacting with the database.
     *
     * @note The 'Entry' object should conform to the specified cve5 schema, including nested structures.
     * @note The 'RocksDBWrapper' object should be properly initialized and connected to the target database.
     *
     * @details The function performs the following steps:
     * 1. Attempts to access remediation data for Windows from the 'Entry' object.
     * 2. If remediation data is not available (empty), it logs an error message and returns.
     * 3. Extracts the CVE identifier (CVE-ID) from the 'Entry' object.
     * 4. Iterates through the available remediation data for Windows:
     *    - Builds a FlatBuffers object containing the remediation information.
     *    - Serializes the FlatBuffers object into binary data.
     *    - Stores the binary data in the RocksDB database, using the CVE-ID as the key.
     * 5. If an exception occurs during this process, it logs an error message.
     *
     * @note This function assumes a specific data structure in the 'Entry' object, including nested objects.
     *       Ensure that the 'Entry' object conforms to the expected schema to avoid runtime errors.
     *
     * @see Entry - The data structure containing CVE and remediation information.
     * @see RocksDBWrapper - The utility class for interacting with RocksDB databases.
     */
    static void storeVulnerabilityRemediation(const cve_v5::Entry* data, utils::rocksdb::IRocksDBWrapper* feedDatabase)
    {
        if (!(data->containers()->cna() && data->containers()->cna()->x_remediations()))
        {
            return;
        }

        const auto remediations = data->containers()->cna()->x_remediations()->windows();

        if (!remediations)
        {
            LOG_ERROR("Remediations database is empty.");
            return;
        }

        flatbuffers::FlatBufferBuilder builder;
        std::vector<flatbuffers::Offset<flatbuffers::String>> updatesVec;
        std::for_each(
            remediations->begin(),
            remediations->end(),
            [&builder, &updatesVec, functionName = logging::getLambdaName(__FUNCTION__, "processRemediationUpdates")](
                const cve_v5::Remediation* remediation)
            {
                auto updatesCve5 = remediation->anyOf();
                if (!updatesCve5)
                {
                    LOG_ERROR_L(functionName.c_str(), "No updates available.");
                    return;
                }

                for (size_t idxUpdate = 0; idxUpdate < updatesCve5->size(); idxUpdate++)
                {
                    updatesVec.emplace_back(
                        builder.CreateString(updatesCve5->Get(static_cast<unsigned int>(idxUpdate))->c_str()));
                }
            });

        if (!updatesVec.empty())
        {
            const auto updates = builder.CreateVector(updatesVec);
            const auto fbbRemediation = NSVulnerabilityScanner::CreateRemediationInfo(builder, updates);
            builder.Finish(fbbRemediation);

            rocksdb::Slice value(reinterpret_cast<const char*>(builder.GetBufferPointer()), builder.GetSize());

            if (!feedDatabase->columnExists(REMEDIATIONS_COLUMN))
            {
                feedDatabase->createColumn(REMEDIATIONS_COLUMN);
            }

            feedDatabase->put(data->cveMetadata()->cveId()->c_str(), value, REMEDIATIONS_COLUMN);
        }
    }

    /**
     * @brief Deletes a remediation from the database
     *
     * @param data Flatbuffer object containing the CVE information.
     * @param feedDatabase rocksDB wrapper instance.
     */
    static void removeRemediation(const cve_v5::Entry* data, utils::rocksdb::IRocksDBWrapper* feedDatabase)
    {
        if (!data->cveMetadata() || !data->cveMetadata()->cveId())
        {
            return;
        }

        if (!feedDatabase->columnExists(REMEDIATIONS_COLUMN))
        {
            return;
        }

        std::string key {data->cveMetadata()->cveId()->str()};
        feedDatabase->delete_(key, REMEDIATIONS_COLUMN);
    }
};

#endif // _UPDATE_CVE_REMEDIATIONS_HPP
