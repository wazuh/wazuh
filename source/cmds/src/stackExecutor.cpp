
#include "stackExecutor.hpp"

#include <exception>

#include <logging/logging.hpp>

namespace cmd
{

void StackExecutor::add(std::function<void()> func)
{
    m_stack.push_back(func);
};

void StackExecutor::execute()
{
    while (!m_stack.empty())
    {
        auto func = m_stack.back();
        m_stack.pop_back();
        try
        {
            func();
        }
        catch (const std::exception& e)
        {
            WAZUH_LOG_ERROR("Engine stack executor: An error occurred while trying to "
                            "execute a command: {}",
                            e.what());
        }
    }
};

} // namespace cmd
