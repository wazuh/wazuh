#include <mmdb/manager.hpp>

#include "handler.hpp"

namespace mmdb
{

void Manager::addHandler(const std::string& name, const std::string& mmdbPath) 
{
    if (m_handlers.find(name) != m_handlers.end())
    {
        throw std::runtime_error {"Handler already exists"};
    }
    if (mmdbPath.empty())
    {
        throw std::runtime_error {"MMDB path is empty"};
    }

    auto handler = std::make_shared<Handler>(mmdbPath);
    auto error = handler->open();
    if (error)
    {
        throw std::runtime_error {error->message};
    }
    m_handlers[name] = handler;
}

void Manager::removeHandler(const std::string& name) 
{
    m_handlers.erase(name);
}

base::RespOrError<std::shared_ptr<IHandler>> Manager::getHandler(const std::string& name) const 
{
    auto it = m_handlers.find(name);
    if (it == m_handlers.end())
    {
        return base::Error {"Handler does not exist"};
    }
    return it->second;
}

} // namespace mmdb
