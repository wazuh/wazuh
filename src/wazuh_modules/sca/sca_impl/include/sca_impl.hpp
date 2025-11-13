#pragma once

#include <isca_policy.hpp>

#include <idbsync.hpp>
#include <ifilesystem_wrapper.hpp>
#include <sca_utils.hpp>
#include "iagent_sync_protocol.hpp"

#include <json.hpp>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

/// @brief Type alias for YAML to JSON conversion function
using YamlToJsonFunc = std::function<nlohmann::json(const std::string&)>;

class SecurityConfigurationAssessment
{
    public:
        /// @brief Constructor
        /// @param dbPath Path to the database file
        /// @param dbSync Pointer to IDBSync for database synchronization
        /// @param fileSystemWrapper File system wrapper for file operations
        SecurityConfigurationAssessment(std::string dbPath,
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
                   std::chrono::seconds scanInterval,
                   const int commandsTimeout,
                   const bool remoteEnabled,
                   const std::vector<sca::PolicyData>& policies,
                   const YamlToJsonFunc& yamlToJsonFunc = nullptr);

        /// @copydoc IModule::Stop
        void Stop() ;

        /// @copydoc IModule::Name
        const std::string& Name() const ;

        /// @brief Set the function to be called for stateless messages
        /// @param pushMessage Function to push stateless messages
        void SetPushStatelessMessageFunction(const std::function<int(const std::string&)>& pushMessage);

        /// @brief Set the function to be called for stateful messages
        /// @param pushMessage Function to push stateful messages
        void SetPushStatefulMessageFunction(const std::function<int(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)>& pushMessage);

        /// @brief Set the global wm_exec function pointer (static)
        /// @param wmExecFunc Function pointer to wm_exec
        static void SetGlobalWmExecFunction(int (*wmExecFunc)(char*, char**, int*, int, const char*));

        /// @brief Get the global wm_exec function pointer (static)
        /// @return Function pointer to wm_exec or nullptr if not set
        static int (*GetGlobalWmExecFunction())(char*, char**, int*, int, const char*);

        /// @brief Initialize the sync protocol
        /// @param moduleName Name of the module
        /// @param syncDbPath Path to the sync database
        /// @param mqFuncs Message queue functions
        void initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, MQ_Functions mqFuncs);

        /// @brief Synchronize the module
        /// @param mode Synchronization mode
        /// @param timeout Timeout for the synchronization
        /// @param retries Number of retries
        /// @param maxEps Maximum number of events per second
        /// @return true if synchronization was successful, false otherwise
        bool syncModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps);

        /// @brief Persist a difference
        /// @param id Identifier of the record
        /// @param operation Operation type
        /// @param index Index of the record
        /// @param data Data to be persisted
        /// @param version Version of the data
        void persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version);

        /// @brief Parse a sync response buffer
        /// @param data Pointer to the data buffer
        /// @param length Length of the data buffer
        /// @return true if parsing was successful, false otherwise
        bool parseResponseBuffer(const uint8_t* data, size_t length);

        /// @brief Notify that data associated with specified indices needs to be cleaned.
        /// @param indices Vector of indices whose data needs to be cleaned.
        /// @param timeout Timeout value in seconds for the operation.
        /// @param retries Number of retry attempts on failure.
        /// @param maxEps Maximum events per second during the operation.
        /// @return true if the operation succeeds, false otherwise.
        bool notifyDataClean(const std::vector<std::string>& indices, std::chrono::seconds timeout, unsigned int retries, size_t maxEps);

        /// @brief Delete the database
        void deleteDatabase();

    protected:
        /// @brief List of policies
        std::vector<std::unique_ptr<ISCAPolicy>> m_policies;

    private:
        /// @brief Get the create statement for the database
        std::string GetCreateStatement() const;

        /// @brief SCA module name
        std::string m_name = "SCA";

        /// @brief Pointer to IDBSync
        std::shared_ptr<IDBSync> m_dBSync;

        /// @brief Function for pushing stateless event messages
        std::function<int(const std::string&)> m_pushStatelessMessage;

        /// @brief Function for pushing stateful event messages
        std::function<int(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> m_pushStatefulMessage;

        /// @brief Pointer to a file system wrapper
        std::shared_ptr<IFileSystemWrapper> m_fileSystemWrapper;

        /// @brief Flag indicating whether the module is enabled
        bool m_enabled = true;

        /// @brief Flag indicating whether to scan on start
        bool m_scanOnStart = true;

        /// @brief Scan interval in seconds
        std::chrono::seconds m_scanInterval = std::chrono::seconds(3600);

        /// @brief Flag to keep the module running
        std::atomic<bool> m_keepRunning {true};

        /// @brief Condition variable for sleep interruption
        std::condition_variable m_cv;

        /// @brief Mutex for condition variable
        std::mutex m_mutex;

        /// @brief Commands timeout for policy execution
        int m_commandsTimeout = 0;

        /// @brief Flag indicating whether remote policies are enabled
        bool m_remoteEnabled = false;

        /// @brief Vector of policy data
        std::vector<sca::PolicyData> m_policiesData;

        /// @brief YAML to JSON conversion function
        YamlToJsonFunc m_yamlToJsonFunc;

        /// @brief Static/global function pointer to wm_exec
        static int (*s_wmExecFunc)(char*, char**, int*, int, const char*);

        /// @brief Path to the sync protocol
        std::unique_ptr<IAgentSyncProtocol> m_spSyncProtocol;
};
