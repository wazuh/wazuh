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

void sca_set_push_functions(push_stateless_func stateless_func, push_stateful_func stateful_func)
{
    g_push_stateless_func = stateless_func;
    g_push_stateful_func = stateful_func;
}

void sca_start(log_callback_t callbackLog, const struct wm_sca_t* sca_config)
{
    std::function<void(const modules_log_level_t, const std::string&)> callbackLogWrapper
    {
        [callbackLog](const modules_log_level_t level, const std::string & data)
        {
            callbackLog(level, data.c_str(), WM_SCA_LOGTAG);
        }};

    std::function<void(const std::string&)> callbackErrorLogWrapper
    {
        [callbackLog](const std::string & data)
        {
            callbackLog(LOG_ERROR, data.c_str(), WM_SCA_LOGTAG);
        }};

    try
    {
        SCA::instance().init(std::move(callbackLogWrapper));
        SCA::instance().setup(sca_config);
        SCA::instance().run();
    }
    catch (const std::exception& ex)
    {
        callbackErrorLogWrapper(ex.what());
    }
}

void sca_stop()
{
    SCA::instance().destroy();
}

int sca_sync_message(const char* data)
{
    int ret {-1};

    try
    {
        SCA::instance().push(data);
        ret = 0;
    }
    catch (...)
    {
    }

    return ret;
}

void sca_set_wm_exec(wm_exec_callback_t wm_exec_callback)
{
    SecurityConfigurationAssessment::SetGlobalWmExecFunction(wm_exec_callback);
}

void sca_set_yaml_to_cjson_func(yaml_to_cjson_func yaml_func)
{
    g_yaml_to_cjson_func = yaml_func;
}

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

void SCA::init(const std::function<void(const modules_log_level_t, const std::string&)> logFunction)
{
    LoggingHelper::setLogCallback(logFunction);

    if (!m_sca)
    {
        m_sca = std::make_unique<SecurityConfigurationAssessment>(SCA_DB_DISK_PATH);

        auto persistStatefulMessage = [](const std::string & message) -> int
        {
            if (g_push_stateful_func)
            {
                return g_push_stateful_func(message.c_str());
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
        const auto scanInterval = sca_config->scan_config.interval > 0 ?
                                  static_cast<std::time_t>(sca_config->scan_config.interval) : 3600;

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
        m_sca->Setup(enabled, scan_on_start, scanInterval, commandsTimeout, remoteEnabled, policies, yaml_file_to_json_cpp);
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

void SCA::push(const std::string&)
{
}

#ifdef __cplusplus
}
#endif
