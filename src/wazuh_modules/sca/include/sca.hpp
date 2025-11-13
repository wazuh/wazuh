#pragma once

#include "sca.h"
#include <sca_impl.hpp>

#include <functional>
#include <memory>
#include <string>

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

/// @brief Security Configuration Assessment (SCA) module wrapper class.
///
/// This class provides a C++ interface for the Wazuh SCA module. It wraps
/// the SecurityConfigurationAssessment C++ implementation and provides lifecycle
/// management methods for initialization, configuration, execution, and cleanup.
///
/// The SCA module performs security configuration assessments by running
/// predefined policies and checks against the system configuration.
class EXPORTED SCA final
{
    public:
        /// @brief Gets the singleton instance of the SCA class.
        ///
        /// @return Reference to the singleton SCA instance
        static SCA& instance()
        {
            static SCA s_instance;
            return s_instance;
        }

        /// @brief Initializes the SCA module.
        ///
        /// Sets up the SecurityConfigurationAssessment implementation with database path,
        /// sync protocol parameters, and message handling functions. Must be called before
        /// setup() and run().
        ///
        /// @throws std::exception if initialization fails
        void init();

        /// @brief Configures the SCA module with the provided configuration.
        ///
        /// Applies the configuration settings including scan intervals, policy paths,
        /// timeout values, and remote command settings. Must be called after init()
        /// and before run().
        ///
        /// @param sca_config Pointer to the SCA configuration structure containing
        ///                   scan settings, policies, and other module parameters
        void setup(const struct wm_sca_t* sca_config);

        /// @brief Starts the SCA module execution.
        ///
        /// Begins the security configuration assessment process according to the
        /// configured policies and scan intervals. Must be called after init()
        /// and setup().
        void run();

        /// @brief Stops and cleans up the SCA module.
        ///
        /// Stops all running assessments, cleans up resources, and resets the
        /// internal SecurityConfigurationAssessment instance.
        void destroy();

        /// @brief Synchronizes the SCA module with the centralized database.
        ///
        /// Performs database synchronization using the specified mode, handling
        /// both full and delta synchronization with configurable timeout and retry
        /// parameters.
        ///
        /// @param mode Synchronization mode (FULL or DELTA)
        /// @param timeout Maximum time to wait for synchronization completion
        /// @param retries Number of retry attempts on failure
        /// @param maxEps Maximum events per second during synchronization
        /// @return true if synchronization succeeds, false otherwise
        bool syncModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps);

        /// @brief Persists a difference entry for synchronization.
        ///
        /// Records changes in the SCA state for later synchronization with the
        /// central database. Used to track CREATE, MODIFY, and DELETE operations
        /// on SCA assessment results.
        ///
        /// @param id Unique identifier for the difference entry
        /// @param operation Type of operation (CREATE, MODIFY, DELETE, NO_OP)
        /// @param index Index or key associated with the change
        /// @param data Serialized data content of the change
        /// @param version Version of the data
        void persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version);

        /// @brief Parses a response buffer from synchronization operations.
        ///
        /// Processes binary response data received during database synchronization
        /// operations, extracting and handling the contained information.
        ///
        /// @param data Pointer to the binary response data buffer
        /// @param length Size of the response data buffer in bytes
        /// @return true if parsing succeeds, false on error or invalid data
        bool parseResponseBuffer(const uint8_t* data, size_t length);

        /// @brief Notifies that data associated with specified indices needs to be cleaned.
        /// @param indices Vector of indices whose data needs to be cleaned.
        /// @param timeout Timeout value in seconds for the operation.
        /// @param retries Number of retry attempts on failure.
        /// @param maxEps Maximum events per second during the operation.
        /// @return true if the operation succeeds, false otherwise.
        bool notifyDataClean(const std::vector<std::string>& indices, std::chrono::seconds timeout, unsigned int retries, size_t maxEps);

        /// @brief Deletes the database.
        void deleteDatabase();

        /// @brief Handles query commands for the SCA module.
        /// @param jsonQuery JSON-formatted query command string
        /// @return JSON-formatted response string
        std::string query(const std::string& jsonQuery);

    private:
        /// @brief Private constructor for singleton pattern.
        SCA();

        /// @brief Default destructor.
        ~SCA() = default;

        /// @brief Deleted copy constructor to prevent copying.
        SCA(const SCA&) = delete;

        /// @brief Deleted assignment operator to prevent copying.
        SCA& operator=(const SCA&) = delete;

        /// @brief Pointer to the SecurityConfigurationAssessment implementation.
        ///
        /// Manages the actual SCA functionality including policy execution,
        /// result processing, and database operations.
        std::unique_ptr<SecurityConfigurationAssessment> m_sca;
};
