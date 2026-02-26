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
#include <map>
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

        /// @brief Transforms the compliance data stored in the DB into the structured
        ///        object format expected by the new indexer schema.
        ///
        /// Mirrors SCAEventHandler::TransformComplianceToIndexerFormat for use in the
        /// recovery path (header-only context). See that function for full documentation.
        ///
        /// @param complianceStr JSON string as stored in the sca_check.compliance column.
        /// @return Structured JSON object for the indexer, or null if no mappable data.
        inline nlohmann::json transformComplianceToIndexerFormat(const std::string& complianceStr)
        {
            struct Mapping
            {
                std::string targetKey;
                std::string version;
            };

            static const std::map<std::string, Mapping> KEY_MAP =
            {
                {"cmmc_v2.0",         {"cmmc",          "2.0"  }},
                {"cmmc_v2.1",         {"cmmc",          "2.1"  }},
                {"fedramp",           {"fedramp",        ""     }},
                {"gdpr",              {"gdpr",           ""     }},
                {"gdpr_IV",           {"gdpr",           ""     }},
                {"hipaa",             {"hipaa",          ""     }},
                {"iso_27001-2013",    {"iso_27001",      "2013" }},
                {"iso_27001-2022",    {"iso_27001",      "2022" }},
                {"mitre_mitigations", {"mitre_attack",   ""     }},
                {"mitre_tactics",     {"mitre_attack",   ""     }},
                {"mitre_techniques",  {"mitre_attack",   ""     }},
                {"nis2",              {"nis2",           ""     }},
                {"nist_800_171",      {"nist_800_171",   ""     }},
                {"nist_800-171",      {"nist_800_171",   ""     }},
                {"nist_sp_800-171",   {"nist_800_171",   ""     }},
                {"nist_800_53",       {"nist_800_53",    ""     }},
                {"nist_800-53",       {"nist_800_53",    ""     }},
                {"nist_sp_800-53",    {"nist_800_53",    ""     }},
                {"pci_dss",           {"pci_dss",        ""     }},
                {"pci_dss_v3.2.1",    {"pci_dss",        "3.2.1"}},
                {"pci_dss_3.2.1",     {"pci_dss",        "3.2.1"}},
                {"pci_dss_v4.0",      {"pci_dss",        "4.0"  }},
                {"pci_dss_4.0",       {"pci_dss",        "4.0"  }},
                {"soc_2",             {"tsc",            ""     }},
                {"tsc",               {"tsc",            ""     }},
            };

            // Canonical metadata for each target framework (standardized per standards body,
            // not organization-specific). These values are fixed for every deployment.
            struct FrameworkMeta
            {
                std::string name;
                std::string publisher;
                std::string category;
            };

            static const std::map<std::string, FrameworkMeta> FRAMEWORK_META =
            {
                {"cmmc",         {"Cybersecurity Maturity Model Certification",               "U.S. Department of Defense",                    "cybersecurity"           }},
                {"fedramp",      {"Federal Risk and Authorization Management Program",         "U.S. General Services Administration",           "federal-cloud-security"  }},
                {"gdpr",         {"General Data Protection Regulation",                       "European Union",                                "data-protection"         }},
                {"hipaa",        {"Health Insurance Portability and Accountability Act",       "U.S. Department of Health and Human Services",   "healthcare"              }},
                {"iso_27001",    {"ISO/IEC 27001 Information Security Management",             "ISO/IEC",                                       "information-security"    }},
                {"mitre_attack", {"MITRE ATT&CK",                                             "MITRE Corporation",                             "threat-intelligence"     }},
                {"nis2",         {"Network and Information Security Directive 2",              "European Union",                                "cybersecurity"           }},
                {"nist_800_171", {"NIST SP 800-171 Protecting Controlled Unclassified Info",   "NIST",                                          "federal-information-systems"}},
                {"nist_800_53",  {"NIST SP 800-53 Security and Privacy Controls",              "NIST",                                          "federal-information-systems"}},
                {"pci_dss",      {"Payment Card Industry Data Security Standard",              "PCI Security Standards Council",                "payment-security"        }},
                {"tsc",          {"Trust Services Criteria",                                   "AICPA",                                         "service-organization"    }},
            };

            nlohmann::json parsed;

            try
            {
                parsed = nlohmann::json::parse(complianceStr);
            }
            catch (const std::exception&)
            {
                return nullptr;
            }

            if (parsed.empty())
            {
                return nullptr;
            }

            // New format: compliance is already a structured object matching the indexer
            // schema (e.g. {"cmmc":{"requirements":[...],"version":"2.0"}, ...}).
            // Pass it through directly without transformation.
            if (parsed.is_object())
            {
                return parsed;
            }

            if (!parsed.is_array())
            {
                return nullptr;
            }

            // Old format: compliance is an array of single-key objects
            // (e.g. [{"cmmc_v2.0":["AC.L1-3.1.1"]},{"hipaa":["164.308"]}]).
            // Apply key mapping and aggregate requirements.

            struct FrameworkData
            {
                std::vector<std::string> requirements;
                std::vector<std::string> versions;
            };

            std::map<std::string, FrameworkData> accum;

            for (const auto& item : parsed)
            {
                if (!item.is_object())
                {
                    continue;
                }

                for (auto it = item.begin(); it != item.end(); ++it)
                {
                    auto mappingIt = KEY_MAP.find(it.key());

                    if (mappingIt == KEY_MAP.end())
                    {
                        continue;
                    }

                    const auto& mapping = mappingIt->second;
                    auto& data = accum[mapping.targetKey];

                    if (!mapping.version.empty())
                    {
                        bool alreadyPresent = false;

                        for (const auto& v : data.versions)
                        {
                            if (v == mapping.version)
                            {
                                alreadyPresent = true;
                                break;
                            }
                        }

                        if (!alreadyPresent)
                        {
                            data.versions.push_back(mapping.version);
                        }
                    }

                    const auto& values = it.value();

                    if (values.is_array())
                    {
                        for (const auto& val : values)
                        {
                            if (val.is_string())
                            {
                                data.requirements.push_back(val.get<std::string>());
                            }
                        }
                    }
                }
            }

            if (accum.empty())
            {
                return nullptr;
            }

            nlohmann::json result = nlohmann::json::object();

            for (const auto& [framework, data] : accum)
            {
                nlohmann::json frameworkObj = nlohmann::json::object();
                frameworkObj["requirements"] = data.requirements;

                if (data.versions.size() == 1)
                {
                    frameworkObj["version"] = data.versions.front();
                }
                else if (data.versions.size() > 1)
                {
                    frameworkObj["version"] = data.versions;
                }

                auto metaIt = FRAMEWORK_META.find(framework);

                if (metaIt != FRAMEWORK_META.end())
                {
                    frameworkObj["name"]      = metaIt->second.name;
                    frameworkObj["publisher"] = metaIt->second.publisher;
                    frameworkObj["category"]  = metaIt->second.category;
                }

                result[framework] = frameworkObj;
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
                auto structured = transformComplianceToIndexerFormat(check["compliance"].get<std::string>());
                check["compliance"] = structured.is_null() ? nlohmann::json(nullptr) : structured;
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
