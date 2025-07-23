#include <sca.hpp>
#include <sca_impl.hpp>

#include <iostream>

#ifdef __cplusplus
extern "C"
{
#endif

#include "../../wm_sca.h"
#include "../wazuh_modules/wmodules_def.h"

void sca_start2(log_callback_t callbackLog)
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

SCA::SCA()
: m_logFunction {nullptr}
{
}

void SCA::init(const std::function<void(const modules_log_level_t, const std::string&)> logFunction)
{
    // TODO Start doing whatever the module does
    m_sca = std::make_unique<SecurityConfigurationAssessment>(".", "agent-uuid-placeholder");
}

void SCA::destroy()
{
    // TODO Stop doing whatever the module is doing and clean up
    m_sca.reset();
}

void SCA::push(const std::string& data)
{
}

#ifdef __cplusplus
}
#endif
