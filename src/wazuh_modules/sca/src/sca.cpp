#include <sca.hpp>
#include <sca_impl.hpp>

#include <iostream>
#include <cJSON.h>
#include <json.hpp>

#ifdef __cplusplus
extern "C"
{
#endif

#include "../../wm_sca.h"
#include "../wazuh_modules/wmodules_def.h"

#include "logging_helper.hpp"

#include <unistd.h>
#include <chrono>

/* SCA db directory */
#ifndef WAZUH_UNIT_TESTING
#define SCA_DB_DISK_PATH "queue/sca/db/sca.db"
#else
#ifndef WIN32
#define SCA_DB_DISK_PATH    "./sca.db"
#else
#define SCA_DB_DISK_PATH    ".\\sca.db"
#endif // WIN32
#endif // WAZUH_UNIT_TESTING

static push_stateless_func g_push_stateless_func = NULL;
static push_stateful_func g_push_stateful_func = NULL;
static yaml_to_cjson_func g_yaml_to_cjson_func = NULL;

static const char* g_module_name = NULL;
static const char* g_sync_db_path = NULL;
static const MQ_Functions* g_mq_functions = NULL;

/// @brief Sets the message pushing functions for SCA module.
///
/// Configures the callback functions used to send stateless and stateful
/// messages from the SCA module to other Wazuh components.
///
/// @param stateless_func Function pointer for sending stateless messages
/// @param stateful_func Function pointer for sending stateful messages with persistence
void sca_set_push_functions(push_stateless_func stateless_func, push_stateful_func stateful_func)
{
    g_push_stateless_func = stateless_func;
    g_push_stateful_func = stateful_func;
}

/// @brief Sets synchronization parameters for the SCA module.
///
/// Configures the module name, database path, and message queue functions
/// required for database synchronization operations.
///
/// @param module_name Name identifier for the SCA module
/// @param sync_db_path Path to the synchronization database file
/// @param mq_funcs Pointer to message queue function structure for communication
void sca_set_sync_parameters(const char* module_name, const char* sync_db_path, const MQ_Functions* mq_funcs)
{
    g_module_name = module_name;
    g_sync_db_path = sync_db_path;
    g_mq_functions = mq_funcs;
}

/// @brief Starts the SCA module with the given configuration.
///
/// Initializes, configures, and starts the SCA module execution using the
/// provided configuration structure. Handles exceptions by logging errors.
///
/// @param sca_config Pointer to the SCA configuration structure containing
///                   module settings, policies, and scan parameters
void sca_start(const struct wm_sca_t* sca_config)
{
    try
    {
        SCA::instance().init();
        SCA::instance().setup(sca_config);
        SCA::instance().run();
    }
    catch (const std::exception& ex)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, ex.what());
    }
}

/// @brief Stops the SCA module execution.
///
/// Cleanly shuts down the SCA module, stopping all assessments and
/// releasing allocated resources.
void sca_stop()
{
    SCA::instance().destroy();
}

/// @brief Sets the logging callback function for the SCA module.
///
/// Configures the logging mechanism by providing a callback function that
/// will be used to output log messages with appropriate level and tagging.
///
/// @param log_callback Function pointer to the logging callback that accepts
///                     log level, message data, and log tag parameters
void sca_set_log_function(log_callback_t log_callback)
{
    std::function<void(const modules_log_level_t, const std::string&)> logWrapper
    {
        [log_callback](const modules_log_level_t level, const std::string & data)
        {
            log_callback(level, data.c_str(), WM_SCA_LOGTAG);
        }
    };

    LoggingHelper::setLogCallback(logWrapper);
}

/// @brief Sets the command execution callback function for the SCA module.
///
/// Configures the callback function used to execute system commands during
/// security configuration assessments. This allows the SCA module to run
/// policy checks that require command execution.
///
/// @param wm_exec_callback Function pointer to the command execution callback
void sca_set_wm_exec(wm_exec_callback_t wm_exec_callback)
{
    SecurityConfigurationAssessment::SetGlobalWmExecFunction(wm_exec_callback);
}

/// @brief Sets the YAML to cJSON conversion function for the SCA module.
///
/// Configures the callback function used to parse YAML policy files and
/// convert them to cJSON format for processing by the SCA module.
///
/// @param yaml_func Function pointer to the YAML parsing callback that
///                  converts YAML files to cJSON structures
void sca_set_yaml_to_cjson_func(yaml_to_cjson_func yaml_func)
{
    g_yaml_to_cjson_func = yaml_func;
}

/// @brief Converts a cJSON object to an nlohmann::json object.
///
/// Helper function that converts cJSON structures to nlohmann::json format
/// for use with modern C++ JSON processing. Handles memory management and
/// error cases gracefully.
///
/// @param cjson_obj Pointer to the cJSON object to convert
/// @return nlohmann::json object containing the converted data, or empty JSON on error
nlohmann::json cjson_to_nlohmann(cJSON* cjson_obj)
{
    if (!cjson_obj)
    {
        return nlohmann::json{};
    }

    char* json_string = cJSON_Print(cjson_obj);

    if (!json_string)
    {
        return nlohmann::json{};
    }

    try
    {
        nlohmann::json result = nlohmann::json::parse(json_string);
        free(json_string);
        return result;
    }
    catch (const std::exception&)
    {
        free(json_string);
        return nlohmann::json{};
    }
}

/// @brief Converts a YAML file to nlohmann::json format.
///
/// Loads and parses a YAML file using the configured YAML parsing function,
/// then converts the result to nlohmann::json format for C++ processing.
/// Used primarily for loading SCA policy files.
///
/// @param yaml_path Path to the YAML file to parse and convert
/// @return nlohmann::json object containing the parsed YAML data, or empty JSON on error
nlohmann::json yaml_file_to_json_cpp(const std::string& yaml_path)
{
    if (!g_yaml_to_cjson_func)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "YAML to cJSON function not set");
        return nlohmann::json{};
    }

    cJSON* cjson_obj = g_yaml_to_cjson_func(yaml_path.c_str());

    if (!cjson_obj)
    {
        LoggingHelper::getInstance().log(LOG_ERROR, "Failed to convert YAML file to cJSON: " + yaml_path);
        return nlohmann::json{};
    }

    nlohmann::json result = cjson_to_nlohmann(cjson_obj);
    cJSON_Delete(cjson_obj);
    return result;
}

SCA::SCA()
{
}

void SCA::init()
{
    if (!m_sca)
    {
        m_sca = std::make_unique<SecurityConfigurationAssessment>(SCA_DB_DISK_PATH);

        m_sca->initSyncProtocol(g_module_name, g_sync_db_path, *g_mq_functions);

        auto persistStatefulMessage = [](const std::string & id, Operation_t operation, const std::string & index, const std::string & message) -> int
        {
            if (g_push_stateful_func)
            {
                return g_push_stateful_func(id.c_str(), operation, index.c_str(), message.c_str());
            }

            LoggingHelper::getInstance().log(LOG_WARNING, "No stateful message handler set");
            return -1;
        };

        auto sendStatelessMessage = [](const std::string & message) -> int
        {
            if (g_push_stateless_func)
            {
                return g_push_stateless_func(message.c_str());
            }

            LoggingHelper::getInstance().log(LOG_WARNING, "No stateless message handler set");
            return -1;
        };

        m_sca->SetPushStatelessMessageFunction(sendStatelessMessage);
        m_sca->SetPushStatefulMessageFunction(persistStatefulMessage);
    }

    LoggingHelper::getInstance().log(LOG_INFO, "SCA module initialized successfully.");
}

void SCA::setup(const struct wm_sca_t* sca_config)
{
    if (m_sca && sca_config)
    {
        // Extract configuration values from wm_sca_t
        const bool enabled = sca_config->enabled != 0;
        const bool scan_on_start = sca_config->scan_on_start != 0;
        const int commandsTimeout = sca_config->commands_timeout;
        const bool remoteEnabled = sca_config->remote_commands != 0;

        // Extract scan interval from scan_config (default to 3600 seconds if not set)
        const auto scanIntervalInSeconds = sca_config->scan_config.interval > 0
                                           ? std::chrono::seconds(sca_config->scan_config.interval)
                                           : std::chrono::seconds(3600);

        // Extract policy paths if available
        std::vector<sca::PolicyData> policies;

        if (sca_config->policies)
        {
            for (int i = 0; sca_config->policies[i] != nullptr; i++)
            {
                wm_sca_policy_t* policy = sca_config->policies[i];

                if (policy->policy_path)
                {
                    policies.emplace_back(sca::PolicyData{std::string(policy->policy_path), policy->enabled == 1, policy->remote == 1});
                }
            }
        }

        // Call Setup only once during initialization
        m_sca->Setup(enabled,
                     scan_on_start,
                     scanIntervalInSeconds,
                     commandsTimeout,
                     remoteEnabled,
                     policies,
                     yaml_file_to_json_cpp);
    }
}

void SCA::run()
{
    if (m_sca)
    {
        m_sca->Run();
    }
}

void SCA::destroy()
{
    if (!m_sca)
    {
        return;
    }

    m_sca->Stop();
    m_sca.reset();
}

// LCOV_EXCL_START

bool SCA::syncModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps)
{
    if (m_sca)
    {
        return m_sca->syncModule(mode, timeout, retries, maxEps);
    }

    return false;
}

void SCA::persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data)
{
    if (m_sca)
    {
        m_sca->persistDifference(id, operation, index, data);
    }
}

bool SCA::parseResponseBuffer(const uint8_t* data, size_t length)
{
    if (m_sca)
    {
        return m_sca->parseResponseBuffer(data, length);
    }

    return false;
}

/// @brief C-style wrapper for SCA module synchronization.
///
/// Provides a C-compatible interface for triggering database synchronization
/// of the SCA module with configurable parameters.
///
/// @param mode Synchronization mode (MODE_FULL or MODE_DELTA)
/// @param timeout Timeout value in seconds for synchronization operations
/// @param retries Number of retry attempts on synchronization failure
/// @param max_eps Maximum events per second during synchronization
/// @return true if synchronization succeeds, false otherwise
bool sca_sync_module(Mode_t mode, unsigned int timeout, unsigned int retries, unsigned int max_eps)
{
    Mode syncMode = (mode == MODE_FULL) ? Mode::FULL : Mode::DELTA;
    return SCA::instance().syncModule(syncMode, std::chrono::seconds(timeout), retries, max_eps);
}

/// @brief C-style wrapper for persisting SCA differences.
///
/// Provides a C-compatible interface for recording changes in SCA state
/// that need to be synchronized with the central database.
///
/// @param id Unique identifier for the difference entry
/// @param operation Type of operation performed (CREATE, MODIFY, DELETE)
/// @param index Index or key associated with the change
/// @param data Serialized data content of the change
void sca_persist_diff(const char* id, Operation_t operation, const char* index, const char* data)
{
    if (id && index && data)
    {
        Operation cppOperation = (operation == OPERATION_CREATE) ? Operation::CREATE :
                                 (operation == OPERATION_MODIFY) ? Operation::MODIFY :
                                 (operation == OPERATION_DELETE) ? Operation::DELETE_ : Operation::NO_OP;
        SCA::instance().persistDifference(std::string(id), cppOperation, std::string(index), std::string(data));
    }
}

/// @brief C-style wrapper for parsing SCA response buffers.
///
/// Provides a C-compatible interface for processing binary response data
/// received during database synchronization operations.
///
/// @param data Pointer to the binary response data buffer
/// @param length Size of the response data buffer in bytes
/// @return true if parsing succeeds, false on error or invalid data
bool sca_parse_response(const unsigned char* data, size_t length)
{
    if (data)
    {
        return SCA::instance().parseResponseBuffer(data, length);
    }

    return false;
}

// LCOV_EXCL_STOP

#ifdef __cplusplus
}
#endif
