#include "sca.hpp"
SCA::SCA()
    : m_logFunction {nullptr}
{
}

void SCA::init(const std::function<void(const modules_log_level_t, const std::string&)> logFunction)
{
    // TODO Start doing whatever the module does
}

void SCA::destroy()
{
    // TODO Stop doing whatever the module is doing and clean up
}

void SCA::push(const std::string& data) {}