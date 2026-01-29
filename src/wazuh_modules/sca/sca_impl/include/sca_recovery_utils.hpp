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
#include <sstream>
#include <string>

#include "stringHelper.h"
#include "timeHelper.h"

namespace sca
{
    namespace recovery
    {

        /// @brief Convert comma-separated string to JSON array
        /// @param input Comma-separated string
        /// @return JSON array with trimmed values (all whitespace removed from both ends)
        inline nlohmann::json stringToJsonArray(const std::string& input)
        {
            nlohmann::json result = nlohmann::json::array();
            std::istringstream stream(input);
            std::string token;

            while (std::getline(stream, token, ','))
            {
                // Trim all whitespace characters including \n, \r, \t, \v, \f, and spaces
                token = Utils::trim(token, " \t\n\r\v\f");

                if (!token.empty())
                {
                    result.push_back(token);
                }
            }

            return result;
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
                check["compliance"] = stringToJsonArray(check["compliance"].get<std::string>());
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
