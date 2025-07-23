#pragma once

#include <isca_policy.hpp>

#include "idbsync.hpp"
#include <ifilesystem_wrapper.hpp>

#include "wm_exec.h"

#include <json.hpp>

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <vector>

class SecurityConfigurationAssessment
{
public:
    /// @brief Constructor
    /// @param dbFolderPath Path to the database folder
    /// @param agentUUID Agent UUID
    /// @param dbSync Pointer to IDBSync for database synchronization
    /// @param fileSystemWrapper File system wrapper for file operations
    SecurityConfigurationAssessment(std::string dbFolderPath,
                                    std::string agentUUID,
                                    std::shared_ptr<IDBSync> dbSync = nullptr,
                                    std::shared_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr);

    /// @brief Destructor
    ~SecurityConfigurationAssessment() = default;

    /// @brief Deleted copy constructor
    SecurityConfigurationAssessment(const SecurityConfigurationAssessment&) = delete;

    /// @brief Deleted copy assignment operator
    SecurityConfigurationAssessment& operator=(const SecurityConfigurationAssessment&) = delete;

    /// @copydoc IModule::Run
    void Run() ;

    /// @copydoc IModule::Setup
    void Setup(bool enabled,
               bool scanOnStart,
               std::time_t scanInterval,
               const std::vector<std::string>& policies,
               const std::vector<std::string>& disabledPolicies);

    /// @copydoc IModule::Stop
    void Stop() ;

    /// @copydoc IModule::Name
    const std::string& Name() const ;

    /// @copydoc IModule::SetPushMessageFunction
    void SetPushMessageFunction(const std::function<int(const std::string&)>& pushMessage) ;

    /// @brief Set the global wm_exec function pointer (static)
    /// @param wmExecFunc Function pointer to wm_exec
    static void SetGlobalWmExecFunction(int (*wmExecFunc)(char*, char**, int*, int, const char*));

    /// @brief Get the global wm_exec function pointer (static)
    /// @return Function pointer to wm_exec or nullptr if not set
    static int (*GetGlobalWmExecFunction())(char*, char**, int*, int, const char*);

private:
    /// @brief Get the create statement for the database
    std::string GetCreateStatement() const;

    /// @brief SCA db file name
    const std::string SCA_DB_DISK_NAME = "sca.db";

    /// @brief SCA module name
    std::string m_name = "SCA";

    /// @brief Agent UUID
    std::string m_agentUUID {""};

    /// @brief Pointer to IDBSync
    std::shared_ptr<IDBSync> m_dBSync;

    /// @brief Function for pushing event messages
    std::function<int(const std::string&)> m_pushMessage;

    /// @brief Pointer to a file system wrapper
    std::shared_ptr<IFileSystemWrapper> m_fileSystemWrapper;

    /// @brief Flag indicating whether the module is enabled
    bool m_enabled = true;

    /// @brief Flag indicating whether to scan on start
    bool m_scanOnStart = true;

    /// @brief Scan interval in seconds
    std::time_t m_scanInterval = 3600;

    /// @brief List of policies
    std::vector<std::unique_ptr<ISCAPolicy>> m_policies;

    /// @brief Flag to keep the module running
    std::atomic<bool> m_keepRunning {true};

    /// @brief Static/global function pointer to wm_exec
    static int (*s_wmExecFunc)(char*, char**, int*, int, const char*);
};
