#include <sca.hpp>
#include <sca_impl.hpp>

#include <iostream>

#ifdef __cplusplus
extern "C"
{
#endif

#include "../../wm_sca.h"
#include "../wazuh_modules/wmodules_def.h"

#include "logging_helper.hpp"
#include "debug_op.h"
#include "shared.h"
#include "mq_op.h"
#include "atomic.h"
#include "defs.h"

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

int scaQueue = -1;
bool shuttingDown = false;

const long maxEps = 100000; // Hardcoded, but same as syscollector


void sca_start(log_callback_t callbackLog, const struct wm_sca_t* sca_config)
{
    shuttingDown = false;

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
    shuttingDown = true;
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

bool isSCAShuttingDown()
{
    return shuttingDown;
}

SCA::SCA()
{
}

void SCA::init(const std::function<void(const modules_log_level_t, const std::string&)> logFunction)
{
    LoggingHelper::setLogCallback(logFunction);

    scaQueue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS);

    if (scaQueue < 0)
    {
        merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
    }

    if (!m_sca)
    {
        m_sca = std::make_unique<SecurityConfigurationAssessment>(SCA_DB_DISK_PATH, "agent-uuid-placeholder");

        auto persistStatefulMessage = [this](const std::string& message) -> int
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Persisting SCA event: " + message);
            return 0;
        };

        auto sendStatelessMessage = [this](const std::string& message) -> int
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Sending SCA event: " + message);

            if (SendMSGPredicated(scaQueue, message.c_str(), "sca", SCA_MQ, isSCAShuttingDown) < 0)
            {
                merror(QUEUE_SEND);

                if ((scaQueue = StartMQ(DEFAULTQUEUE, WRITE, INFINITE_OPENQ_ATTEMPTS)) < 0)
                {
                    merror_exit(QUEUE_FATAL, DEFAULTQUEUE);
                }

                // Try to send it again
                SendMSGPredicated(scaQueue, message.c_str(), "sca", SCA_MQ, isSCAShuttingDown);
            }

            static atomic_int_t n_msg_sent = ATOMIC_INT_INITIALIZER(0);

            if (atomic_int_inc(&n_msg_sent) >= maxEps)
            {
                sleep(1);
                atomic_int_set(&n_msg_sent, 0);
            }

            return 0;
        };

        m_sca->SetPushStatelessMessageFunction(sendStatelessMessage);
        m_sca->SetPushStatefulMessageFunction(persistStatefulMessage);
    }

    LoggingHelper::getInstance().log(LOG_INFO, "SCA module initialized successfully.");
}

void SCA::setup(const struct wm_sca_t* sca_config)
{
    if (m_sca && sca_config) {
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

        if (sca_config->policies) {
            for (int i = 0; sca_config->policies[i] != nullptr; i++) {
                wm_sca_policy_t* policy = sca_config->policies[i];
                if (policy->policy_path) {
                    policies.emplace_back(sca::PolicyData{std::string(policy->policy_path), policy->enabled == 1, policy->remote == 1});
                }
            }
        }

        // Call Setup only once during initialization
        m_sca->Setup(enabled, scan_on_start, scanInterval, commandsTimeout, remoteEnabled, policies);
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
