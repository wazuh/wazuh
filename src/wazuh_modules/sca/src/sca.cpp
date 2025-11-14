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
#include "../../module_query_errors.h"
#include "../wazuh_modules/wmodules_def.h"

#include "logging_helper.hpp"

#include <unistd.h>
#include <chrono>

static push_stateless_func g_push_stateless_func = NULL;
static push_stateful_func g_push_stateful_func = NULL;
static yaml_to_cjson_func g_yaml_to_cjson_func = NULL;

static const char* g_module_name = NULL;
static const char* g_sync_db_path = NULL;
static const MQ_Functions* g_mq_functions = NULL;
static unsigned int g_sync_end_delay = 1;
static unsigned int g_sync_timeout = 30;
static unsigned int g_sync_retries = 3;
static size_t g_sync_max_eps = 10;

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
/// @param sync_end_delay Delay for synchronization end message in seconds
/// @param timeout Default timeout for synchronization operations in seconds
/// @param retries Default number of retries for synchronization operations
/// @param maxEps Default maximum events per second for synchronization operations
void sca_set_sync_parameters(const char* module_name, const char* sync_db_path, const MQ_Functions* mq_funcs, unsigned int sync_end_delay, unsigned int timeout, unsigned int retries, size_t maxEps)
{
    g_module_name = module_name;
    g_sync_db_path = sync_db_path;
    g_mq_functions = mq_funcs;
    g_sync_end_delay = sync_end_delay;
    g_sync_timeout = timeout;
    g_sync_retries = retries;
    g_sync_max_eps = maxEps;
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

void sca_init()
{
    try
    {
        SCA::instance().init();
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
        try
        {
            m_sca = std::make_unique<SecurityConfigurationAssessment>(SCA_DB_DISK_PATH);

            m_sca->initSyncProtocol(g_module_name, g_sync_db_path, *g_mq_functions, std::chrono::seconds(g_sync_end_delay), std::chrono::seconds(g_sync_timeout), g_sync_retries, g_sync_max_eps);

            auto persistStatefulMessage = [](const std::string & id, Operation_t operation, const std::string & index, const std::string & message, uint64_t version) -> int
            {
                if (g_push_stateful_func)
                {
                    return g_push_stateful_func(id.c_str(), operation, index.c_str(), message.c_str(), version);
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

            LoggingHelper::getInstance().log(LOG_INFO, "SCA module initialized successfully.");
        }
        catch (const std::exception& ex)
        {
            LoggingHelper::getInstance().log(LOG_ERROR, "Failed to initialize SCA module: " + std::string(ex.what()));
            // Clean up partial initialization
            m_sca.reset();
            // Re-throw so outer layer can handle
            throw;
        }
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_INFO, "SCA module already initialized.");
    }
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
}

// LCOV_EXCL_START

bool SCA::syncModule(Mode mode)
{
    if (m_sca)
    {
        return m_sca->syncModule(mode);
    }

    return false;
}

void SCA::persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version)
{
    if (m_sca)
    {
        m_sca->persistDifference(id, operation, index, data, version);
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

bool SCA::notifyDataClean(const std::vector<std::string>& indices)
{
    if (m_sca)
    {
        return m_sca->notifyDataClean(indices);
    }

    return false;
}

void SCA::deleteDatabase()
{
    if (m_sca)
    {
        m_sca->deleteDatabase();
    }
}

// LCOV_EXCL_START

// Excluded from code coverage as it is not the real implementation of the query method.
// This is just a placeholder to comply with the module interface requirements.
// The real implementation should be done in the future iterations.
std::string SCA::query(const std::string& jsonQuery)
{
    // Log the received query
    LoggingHelper::getInstance().log(LOG_DEBUG, "Received query: " + jsonQuery);

    try
    {
        // Parse JSON command
        nlohmann::json query_json = nlohmann::json::parse(jsonQuery);

        if (!query_json.contains("command") || !query_json["command"].is_string())
        {
            nlohmann::json response;
            response["error"] = MQ_ERR_INVALID_PARAMS;
            response["message"] = MQ_MSG_INVALID_PARAMS;
            return response.dump();
        }

        std::string command = query_json["command"];
        nlohmann::json parameters = query_json.contains("parameters") ? query_json["parameters"] : nlohmann::json();

        // Log the command being executed
        LoggingHelper::getInstance().log(LOG_DEBUG, "Executing command: " + command);

        nlohmann::json response;

        // Handle coordination commands with JSON responses
        if (command == "pause")
        {
            response["error"] = MQ_SUCCESS;
            response["message"] = "SCA module paused successfully";
            response["data"]["module"] = "sca";
            response["data"]["action"] = "pause";
        }
        else if (command == "flush")
        {
            response["error"] = MQ_SUCCESS;
            response["message"] = "SCA module flushed successfully";
            response["data"]["module"] = "sca";
            response["data"]["action"] = "flush";
        }
        else if (command == "get_version")
        {
            response["error"] = MQ_SUCCESS;
            response["message"] = "SCA version retrieved";
            response["data"]["version"] = 4;
        }
        else if (command == "set_version")
        {
            // Extract version from parameters
            int version = 0;

            if (parameters.is_object() && parameters.contains("version") && parameters["version"].is_number())
            {
                version = parameters["version"].get<int>();
            }

            response["error"] = MQ_SUCCESS;
            response["message"] = "SCA version set successfully";
            response["data"]["version"] = version;
        }
        else if (command == "resume")
        {
            response["error"] = MQ_SUCCESS;
            response["message"] = "SCA module resumed successfully";
            response["data"]["module"] = "sca";
            response["data"]["action"] = "resume";
        }
        else
        {
            response["error"] = MQ_ERR_UNKNOWN_COMMAND;
            response["message"] = "Unknown SCA command: " + command;
            response["data"]["command"] = command;
        }

        return response.dump();
    }
    catch (const std::exception& ex)
    {
        nlohmann::json response;
        response["error"] = MQ_ERR_INTERNAL;
        response["message"] = "Exception parsing JSON or executing command: " + std::string(ex.what());

        LoggingHelper::getInstance().log(LOG_ERROR, "Query error: " + std::string(ex.what()));
        return response.dump();
    }
}

// LCOV_EXCL_STOP

/// @brief C-style wrapper for SCA module synchronization.
///
/// Provides a C-compatible interface for triggering database synchronization
/// of the SCA module with configurable parameters.
///
/// @param mode Synchronization mode (MODE_FULL or MODE_DELTA)
/// @return true if synchronization succeeds, false otherwise
bool sca_sync_module(Mode_t mode)
{
    Mode syncMode = (mode == MODE_FULL) ? Mode::FULL : Mode::DELTA;
    return SCA::instance().syncModule(syncMode);
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
/// @param version Version of the data
void sca_persist_diff(const char* id, Operation_t operation, const char* index, const char* data, uint64_t version)
{
    if (id && index && data)
    {
        Operation cppOperation = (operation == OPERATION_CREATE) ? Operation::CREATE :
                                 (operation == OPERATION_MODIFY) ? Operation::MODIFY :
                                 (operation == OPERATION_DELETE) ? Operation::DELETE_ : Operation::NO_OP;
        SCA::instance().persistDifference(std::string(id), cppOperation, std::string(index), std::string(data), version);
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

/// @brief C-style wrapper for notifying data clean in SCA module.
/// @param indices Array of index strings to notify as clean
/// @param indices_count Number of indices in the array
/// @return true if the operation succeeds, false otherwise
bool sca_notify_data_clean(const char** indices, size_t indices_count)
{
    if (indices && indices_count > 0)
    {
        std::vector<std::string> indicesVec;
        indicesVec.reserve(indices_count);

        for (size_t i = 0; i < indices_count; ++i)
        {
            if (indices[i])
            {
                indicesVec.emplace_back(indices[i]);
            }
        }

        if (!indicesVec.empty())
        {
            return SCA::instance().notifyDataClean(indicesVec);
        }
    }

    return false;
}

/// @brief C-style wrapper for deleting the SCA database.
void sca_delete_database()
{
    SCA::instance().deleteDatabase();
}

// LCOV_EXCL_STOP

/// @brief Query handler for SCA module.
///
/// Handles query commands sent to the SCA module from other modules.
///
/// @param json_query Json query command string
/// @param output Pointer to output string (caller must free with os_free)
/// @return Length of the output string
size_t sca_query(const char* json_query, char** output)
{
    if (!json_query || !output)
    {
        return 0;
    }

    try
    {
        std::string result = SCA::instance().query(std::string(json_query));
        *output = strdup(result.c_str());
        return strlen(*output);
    }
    catch (const std::exception& ex)
    {
        std::string error = "{\"error\":" + std::to_string(MQ_ERR_EXCEPTION) + ",\"message\":\"Exception in query handler: " + std::string(ex.what()) + "\"}";
        *output = strdup(error.c_str());
        return strlen(*output);
    }
}

#ifdef __cplusplus
}
#endif
