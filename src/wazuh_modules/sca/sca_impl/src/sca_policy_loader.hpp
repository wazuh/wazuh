#pragma once

#include <isca_policy.hpp>

#include <idbsync.hpp>
#include <ifilesystem_wrapper.hpp>

#include <filesystem>
#include <functional>
#include <memory>
#include <json.hpp>
#include <string>
#include <vector>

/// @brief Default DBSync queue size
constexpr auto DBSYNC_QUEUE_SIZE {4096};

/// @brief Default DBSync table names
constexpr auto SCA_POLICY_TABLE_NAME {"sca_policy"};
constexpr auto SCA_CHECK_TABLE_NAME {"sca_check"};

/// @brief Type alias for a function that creates events
using CreateEventsFunc = std::function<void(std::unordered_map<std::string, nlohmann::json> modifiedPoliciesMap,
                                            std::unordered_map<std::string, nlohmann::json> modifiedChecksMap)>;

class SCAPolicyLoader
{
public:
    /// @brief Constructor for SCAPolicyLoader
    /// @param policies A vector of policy files paths to load
    /// @param disabledPolicies A vector of disabled policy files paths
    /// @param fileSystemWrapper A shared pointer to a file system wrapper
    /// @param dBSync A shared pointer to a DBSync object
    SCAPolicyLoader(const std::vector<std::string>& policies,
                    const std::vector<std::string>& disabledPolicies,
                    std::shared_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr,
                    std::shared_ptr<IDBSync> dBSync = nullptr);

    /// @brief Destructor for SCAPolicyLoader
    ~SCAPolicyLoader() = default;

    /// @brief Loads SCA Policies
    /// @returns a vector of SCAPolicy objects
    /// @param createEvents Callback function to generate events. It will be called with two
    /// maps:
    ///   - modifiedPoliciesMap: maps policy ID to the JSON data of the created, modified or deleted policy
    ///   - modifiedChecksMap: maps check ID to the JSON data of the created, modified or deleted check
    std::vector<std::unique_ptr<ISCAPolicy>> LoadPolicies(const CreateEventsFunc& createEvents) const;

    /// @brief Saves SCA Policies into the database
    /// @param data All SCA policies and its checks
    /// @param createEvents Callback function to generate events. It will be called with two
    /// maps:
    ///   - modifiedPoliciesMap: maps policy ID to the JSON data of the created, modified or deleted policy
    ///   - modifiedChecksMap: maps check ID to the JSON data of the created, modified or deleted check
    void SyncPoliciesAndReportDelta(const nlohmann::json& data, const CreateEventsFunc& createEvents) const;

private:
    /// @brief Synchronizes with the DBSync and returns a map of modified policies and checks
    /// @param data SCA policies and checks
    /// @param tableName DBSync table name
    /// @returns a map of modified policies and checks
    std::unordered_map<std::string, nlohmann::json> SyncWithDBSync(const nlohmann::json& data,
                                                                   const std::string& tableName) const;

    /// @brief Synchronizes with the DBSync and updates the result of a check
    /// @param check The check to update
    void UpdateCheckResult(const nlohmann::json& check) const;

    /// @brief Normalizes the structure of a JSON object.
    ///
    /// Ensures "references" field is replaced with "refs" and "title" field is replaced with "name" before the DB
    /// transaction.
    ///
    /// @param data The JSON object to normalize.
    /// @returns The normalized JSON object.
    nlohmann::json NormalizeData(nlohmann::json data) const;

    /// @brief Normalizes the structure of a JSON object and adds checksums for check data.
    ///
    /// Calls NormalizeData and additionally calculates and adds checksums for check entries.
    ///
    /// @param data The JSON object to normalize.
    /// @param tableName The table name to determine if checksum calculation is needed.
    /// @returns The normalized JSON object with checksums added if applicable.
    nlohmann::json NormalizeDataWithChecksum(nlohmann::json data, const std::string& tableName) const;

    std::shared_ptr<IFileSystemWrapper> m_fileSystemWrapper;

    std::vector<std::filesystem::path> m_customPoliciesPaths;
    std::vector<std::filesystem::path> m_disabledPoliciesPaths;

    std::shared_ptr<IDBSync> m_dBSync;
};
