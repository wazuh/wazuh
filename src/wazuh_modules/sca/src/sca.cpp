#include <sca.hpp>
#include <sca_impl.hpp>

#include <iostream>

#ifdef __cplusplus
extern "C"
{
#endif

#include "../../wm_sca.h"
#include "../wazuh_modules/wmodules_def.h"

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

void sca_start(log_callback_t callbackLog, const struct wm_sca_t* sca_config)
{
    std::function<void(const modules_log_level_t, const std::string&)> callbackLogWrapper {
        [callbackLog](const modules_log_level_t level, const std::string& data)
        {
            callbackLog(level, data.c_str(), WM_SCA_LOGTAG);
        }};

    std::function<void(const std::string&)> callbackErrorLogWrapper {
        [callbackLog](const std::string& data)
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

SCA::SCA()
: m_logFunction {nullptr}
{
}

void SCA::init(const std::function<void(const modules_log_level_t, const std::string&)> logFunction)
{
    // TODO Start doing whatever the module does
    m_sca = std::make_unique<SecurityConfigurationAssessment>(SCA_DB_DISK_PATH, "agent-uuid-placeholder");
    m_logFunction = logFunction;

    // TODO remove this, it's only for testing purposes
    // Set a simple print function for m_pushMessage so we can see the SCA checks
    // being processed in the OSSEC log
    auto simplePrintFunction = [this](const std::string& message) -> int {
        if (m_logFunction)
        {
            m_logFunction(LOG_INFO, "SCA Event: " + message);
        }
        else
        {
            std::cout << "SCA Event: " << message << std::endl;
        }
        return 0;
    };

    m_sca->SetPushMessageFunction(simplePrintFunction);

    // logFunction(LOG_INFO, "SCA module initialized successfully.");
}

void SCA::setup(const struct wm_sca_t* sca_config)
{
    if (m_sca && sca_config) {
        // Extract configuration values from wm_sca_t
        bool enabled = sca_config->enabled != 0;
        bool scan_on_start = sca_config->scan_on_start != 0;

        // Extract scan interval from scan_config (default to 3600 seconds if not set)
        const auto scanInterval = sca_config->scan_config.interval > 0 ?
            static_cast<std::time_t>(sca_config->scan_config.interval) : 3600;

        // Extract policy paths if available
        std::vector<std::string> policies;
        std::vector<std::string> disabledPolicies;

        if (sca_config->policies) {
            for (int i = 0; sca_config->policies[i] != nullptr; i++) {
                wm_sca_policy_t* policy = sca_config->policies[i];
                if (policy->policy_path) {
                    if (policy->enabled) {
                        policies.push_back(std::string(policy->policy_path));
                    } else {
                        disabledPolicies.push_back(std::string(policy->policy_path));
                    }
                }
            }
        }
        m_sca->Setup(enabled, scan_on_start, scanInterval, policies, disabledPolicies);
    }
}

void SCA::run()
{
    if (m_sca) {
        m_sca->Run();
    }
}

void SCA::destroy()
{
    if (!m_sca) {
        return;
    }
    m_sca->Stop();
    m_sca.reset();
}

void SCA::push(const std::string& data)
{
}

#ifdef __cplusplus
}
#endif
