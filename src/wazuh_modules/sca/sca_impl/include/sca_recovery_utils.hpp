/*
 * Wazuh SCA
 * Copyright (C) 2015, Wazuh Inc.
 * December 1, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <dbsync.hpp>
#include <idbsync.hpp>
#include <json.hpp>
#include <sca_field_decoder.hpp>
#include <string>

#include "stringHelper.h"
#include "timeHelper.h"

namespace sca
{
    namespace recovery
    {

        /// @brief Convert a stored list column to a JSON array
        /// @param input Serialised JSON array, or a comma-separated string for legacy rows
        /// @return JSON array of elements
        inline nlohmann::json stringToJsonArray(const std::string& input)
        {
            return sca::DecodeStringListField(input);
        }

        /// @brief Normalize check data for stateful message format
        /// @param check Check JSON object (modified in place)
        inline void normalizeCheckForStateful(nlohmann::json& check)
        {
            if (check.contains("refs") && check["refs"].is_string())
            {
                check["references"] = stringToJsonArray(check["refs"].get<std::string>());
                check.erase("refs");
            }

            if (check.contains("compliance") && check["compliance"].is_string())
            {
                try
                {
                    check["compliance"] = nlohmann::json::parse(check["compliance"].get<std::string>());
                }
                catch (const nlohmann::json::parse_error&)
                {
                    check.erase("compliance");
                }
            }

            if (check.contains("mitre") && check["mitre"].is_string())
            {
                try
                {
                    check["mitre"] = nlohmann::json::parse(check["mitre"].get<std::string>());
                }
                catch (const nlohmann::json::parse_error&)
                {
                    check.erase("mitre");
                }
            }

            if (check.contains("rules") && check["rules"].is_string())
            {
                check["rules"] = stringToJsonArray(check["rules"].get<std::string>());
            }

            if (check.contains("policy_id"))
            {
                check.erase("policy_id");
            }

            // Remove internal field not part of indexer schema
            if (check.contains("regex_type"))
            {
                check.erase("regex_type");
            }

            // Remove sync field - internal use only
            if (check.contains("sync"))
            {
                check.erase("sync");
            }
        }

        /// @brief Normalize policy data for stateful message format
        /// @param policy Policy JSON object (modified in place)
        inline void normalizePolicyForStateful(nlohmann::json& policy)
        {
            if (policy.contains("refs") && policy["refs"].is_string())
            {
                policy["references"] = stringToJsonArray(policy["refs"].get<std::string>());
                policy.erase("refs");
            }
        }

        /// @brief Escape single quotes in a string for SQL safety
        /// @param input String to escape
        /// @return Escaped string with single quotes doubled
        inline std::string escapeSqlString(std::string input)
        {
            Utils::replaceAll(input, "'", "''");
            return input;
        }

        /// @brief Get policy data by ID from database
        /// @param policyId Policy ID to look up
        /// @param dbSync Database sync interface
        /// @return Policy JSON object, empty if not found
        inline nlohmann::json getPolicyById(const std::string& policyId, const std::shared_ptr<IDBSync>& dbSync)
        {
            nlohmann::json policy;

            if (!dbSync)
            {
                return policy;
            }

            const std::string escapedPolicyId = escapeSqlString(policyId);
            const std::string filter = "WHERE id = '" + escapedPolicyId + "'";
            auto selectQuery = SelectQuery::builder()
                               .table("sca_policy")
                               .columnList({"id", "name", "description", "file", "refs"})
                               .rowFilter(filter)
                               .build();

            const auto callback = [&policy](ReturnTypeCallback returnTypeCallback, const nlohmann::json & resultData)
            {
                if (returnTypeCallback == SELECTED)
                {
                    policy = resultData;
                }
            };

            dbSync->selectRows(selectQuery.query(), callback);

            return policy;
        }

        /// @brief Build stateful message in the format required by the indexer
        /// @param check Check data from database
        /// @param policy Policy data from database
        /// @return Properly formatted stateful message JSON
        inline nlohmann::json buildStatefulMessage(nlohmann::json check, nlohmann::json policy)
        {
            // Extract and restructure checksum
            nlohmann::json checksumObj = nlohmann::json::object();

            if (check.contains("checksum") && !check["checksum"].get<std::string>().empty())
            {
                checksumObj = {{"hash", {{"sha1", check["checksum"]}}}};
                check.erase("checksum");
            }

            // Build state object with modified_at and document_version
            nlohmann::json state;
            state["modified_at"] = Utils::getCurrentISO8601();

            if (check.contains("version"))
            {
                state["document_version"] = check["version"].get<uint64_t>();
                check.erase("version");
            }

            // Normalize the data
            normalizeCheckForStateful(check);
            normalizePolicyForStateful(policy);

            return {{"checksum", checksumObj}, {"check", check}, {"policy", policy}, {"state", state}};
        }

    } // namespace recovery
} // namespace sca
