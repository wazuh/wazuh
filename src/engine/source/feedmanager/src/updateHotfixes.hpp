/*
 * Wazuh storeRemediationsModel
 * Copyright (C) 2015, Wazuh Inc.
 * May 2, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _UPDATE_HOTFIXES_HPP
#define _UPDATE_HOTFIXES_HPP

#include "base/utils/rocksDBWrapper.hpp"
#include "cve5_generated.h"

constexpr auto HOTFIXES_APPLICATIONS_COLUMN {"hotfixes_applications"};
/**
 * @brief UpdateHotfixes class.
 *
 */
class UpdateHotfixes final
{
public:
    /**
     * @brief Update the hotfix information in the RocksDB Database
     *
     * This function updates the hotfix information for a given vulnerability (CVE) in the RocksDB database.
     * It does so by inverting the relationship between the CVE and hotfix information,
     * going from 'CVE -> Hotfixes' to 'Hotfixes -> CVE'.
     *
     *
     * @param data Pointer to the 'Entry' object containing vulnerability and remediation information.
     * @param feedDatabase Pointer to the 'RocksDB' object for interacting with the database.
     *
     * @note The 'Entry' object should conform to the specified cve5 schema, including nested structures.
     * @note The 'RocksDBWrapper' object should be properly initialized and connected to the target database.
     *
     * @details The function performs the following steps:
     * 1. Attempts to access remediation data for Windows from the 'Entry' object.
     * 2. If remediation data is not available (empty), it returns.
     * 3. Extracts the CVE identifier (CVE-ID) from the 'Entry' object.
     * 4. Iterates through the available remediation data for Windows:
     *    - For each remediation, it checks if any hotfixes are available.
     *    - If hotfixes are available, it iterates through each hotfix and stores it in the database.
     *    - The key for storing the hotfix is generated with the format '${hotfix}_${CVE-ID}'.
     *
     * @note This function assumes a specific data structure in the 'Entry' object, including nested objects.
     *       Ensure that the 'Entry' object conforms to the expected schema to avoid runtime errors.
     *
     * @see Entry - The data structure containing CVE and remediation information.
     * @see RocksDBWrapper - The utility class for interacting with RocksDB databases.
     */
    static void storeVulnerabilityHotfixes(const cve_v5::Entry* data, utils::rocksdb::IRocksDBWrapper* feedDatabase)
    {
        const auto remediations = data->containers()->cna()->x_remediations();
        if (!remediations)
        {
            return;
        }

        const auto windowsRemediations = remediations->windows();
        if (!windowsRemediations)
        {
            return;
        }

        if (!feedDatabase->columnExists(HOTFIXES_APPLICATIONS_COLUMN))
        {
            feedDatabase->createColumn(HOTFIXES_APPLICATIONS_COLUMN);
        }

        const auto cveId = data->cveMetadata()->cveId()->str();

        std::for_each(windowsRemediations->begin(),
                      windowsRemediations->end(),
                      [&feedDatabase, &cveId](const cve_v5::Remediation* remediation)
                      {
                          if (!remediation->anyOf())
                          {
                              return;
                          }

                          for (const auto hotfix : *remediation->anyOf())
                          {
                              const auto key = hotfix->str() + "_" + cveId;
                              feedDatabase->put(key, "", HOTFIXES_APPLICATIONS_COLUMN);
                          }
                      });
    }

    /**
     * @brief Deletes all hotfixes associated with a given vulnerability from the RocksDB database.
     *
     * @param data Pointer to the 'Entry' object containing vulnerability and remediation information.
     * @param feedDatabase rocksDB wrapper instance.
     */
    static void removeHotfix(const cve_v5::Entry* data, utils::rocksdb::IRocksDBWrapper* feedDatabase)
    {
        if (!feedDatabase->columnExists(HOTFIXES_APPLICATIONS_COLUMN))
        {
            return;
        }

        const auto remediations = data->containers()->cna()->x_remediations();
        if (!remediations)
        {
            return;
        }

        const auto windowsRemediations = remediations->windows();
        if (!windowsRemediations)
        {
            return;
        }

        const auto cveId = data->cveMetadata()->cveId()->str();
        std::for_each(windowsRemediations->begin(),
                      windowsRemediations->end(),
                      [&feedDatabase, &cveId](const cve_v5::Remediation* remediation)
                      {
                          if (!remediation->anyOf())
                          {
                              return;
                          }

                          for (const auto hotfix : *remediation->anyOf())
                          {
                              const auto key = hotfix->str() + "_" + cveId;
                              feedDatabase->delete_(key, HOTFIXES_APPLICATIONS_COLUMN);
                          }
                      });
    }
};
#endif // _UPDATE_HOTFIXES_HPP
