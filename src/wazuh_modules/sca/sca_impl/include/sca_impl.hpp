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

class SCASyncManager;

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
        /// @param syncEndDelay Delay for synchronization end message in seconds
        /// @param timeout Timeout for synchronization responses
        /// @param retries Number of retries for synchronization
        /// @param maxEps Maximum events per second
        /// @param integrityInterval Interval in seconds between integrity checks (0 = disabled)
        void initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, MQ_Functions mqFuncs, std::chrono::seconds syncEndDelay, std::chrono::seconds timeout, unsigned int retries,
                              size_t maxEps, std::chrono::seconds integrityInterval);

        /// @brief Synchronize the module
        /// @param mode Synchronization mode
        /// @return true if synchronization was successful, false otherwise
        bool syncModule(Mode mode);

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

        /// @brief Set the sync limit for SCA documents.
        /// @param syncLimit Maximum number of synced checks (0 = unlimited)
        void setSyncLimit(uint64_t syncLimit);

        /// @brief Notify that data associated with specified indices needs to be cleaned.
        /// @param indices Vector of indices whose data needs to be cleaned.
        /// @return true if the operation succeeds, false otherwise.
        bool notifyDataClean(const std::vector<std::string>& indices);

        /// @brief Delete the database
        void deleteDatabase();

        /// @brief Get the maximum version from the sca_check table
        /// @return Maximum version number, or -1 on error, 0 if table is empty
        int getMaxVersion();

        /// @brief Set the version for all rows in the sca_check table
        /// @param version Version number to set
        /// @return 0 on success, -1 on error
        int setVersion(int version);

        /// @brief Pause SCA scanning operations for coordination
        void pause();

        /// @brief Flush pending sync protocol messages
        /// @return 0 on success, -1 on error
        int flush();

        /// @brief Resume SCA scanning operations after coordination
        void resume();

        /// @brief Handles query commands for the SCA module
        /// @param jsonQuery JSON-formatted query command string
        /// @return JSON-formatted response string
        std::string query(const std::string& jsonQuery);

    protected:
        /// @brief List of policies
        std::vector<std::unique_ptr<ISCAPolicy>> m_policies;

        /// @brief Sync protocol for module synchronization
        std::shared_ptr<IAgentSyncProtocol> m_spSyncProtocol;

        /// @brief Flag indicating if a sync operation is currently in progress
        std::atomic<bool> m_syncInProgress {false};

        /// @brief Condition variable for pause/resume coordination
        std::condition_variable m_pauseCv;

        /// @brief Mutex for pause/resume coordination
        std::mutex m_pauseMutex;

    private:
        /// @brief Get the create statement for the database
        std::string GetCreateStatement() const;

        /// @brief Get the upgrade statements for the database
        std::vector<std::string> GetUpgradeStatements() const;


        /// @brief Integrity check interval in seconds (0 = disabled)
        std::chrono::seconds m_integrityInterval = std::chrono::seconds(0);

        /// @brief Check if integrity interval has elapsed
        /// @param currentTime Current timestamp
        /// @return true if check should run
        bool integrityIntervalElapsed(int64_t currentTime);

        /// @brief Get last integrity check timestamp from DB
        /// @return Timestamp in seconds since epoch, 0 if never checked
        int64_t getLastIntegrityCheckTime();

        /// @brief Update last integrity check timestamp in DB
        /// @param timestamp Current time
        void updateLastIntegrityCheckTime(int64_t timestamp);

        /// @brief Perform full recovery: load all checks and resync
        /// @return true on success
        bool performRecovery();

        /// @brief Check with manager if full sync required via checksum
        /// @param checksum Local checksum to validate
        /// @return true if recovery needed
        bool checkIfRecoveryRequired(const std::string& checksum);

        /// @brief Check if DB has data (policies or checks)
        /// @return true if DB contains any policies or checks
        bool hasDataInDatabase();

        /// @brief Handle the case when no policies are available (either at startup or runtime).
        /// If the database has existing data, triggers DataClean to notify the manager and clears DB.
        /// @return true if no cleanup was needed (DB was already empty), false if cleanup was performed or failed
        bool handleNoPoliciesAvailable();

        /// @brief Handle case when all policies are removed from config
        /// Sends DataClean, clears DB, syncs, and signals exit
        /// @return true if DataClean was sent and handled successfully
        bool handleAllPoliciesRemoved();

        /// @brief SCA module name
        std::string m_name = "SCA";

        /// @brief Pointer to IDBSync
        std::shared_ptr<IDBSync> m_dBSync;

        /// @brief SCA sync manager (document limits)
        std::shared_ptr<SCASyncManager> m_syncManager;

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

        /// @brief Flag indicating if scanning is paused for coordination
        std::atomic<bool> m_paused {false};

        /// @brief Flag indicating if a scan is currently in progress
        std::atomic<bool> m_scanInProgress {false};

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

        /// @brief Flag indicating module should exit after DataClean (all policies removed)
        std::atomic<bool> m_exitAfterDataClean {false};

        /// @brief Static/global function pointer to wm_exec
        static int (*s_wmExecFunc)(char*, char**, int*, int, const char*);
};
