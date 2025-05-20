#ifndef _CMD_DETAILS_STACK_EXECUTOR_HPP
#define _CMD_DETAILS_STACK_EXECUTOR_HPP

#include <deque>
#include <exception>
#include <functional>

#include <base/logging.hpp>

namespace cmd::details
{

/**
 * @brief Class to execute a stack of functions
 *
 * The functions are executed in reverse order of insertion (LIFO)
 */
class StackExecutor
{
private:
    std::deque<std::function<void()>> m_stack; ///< Stack of functions

public:
    StackExecutor()
        : m_stack() {}; ///< Default constructor
    ~StackExecutor() = default;

    /**
     * @brief Add a function to the stack
     *
     * @param func Function to add
     */
    void add(std::function<void()> func) { m_stack.push_back(func); }

    /**
     * @brief Execute the stack of functions.
     *
     * The functions are executed in reverse order of insertion (LIFO), and the stack is
     * cleared.
     */
    void execute()
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
                LOG_ERROR("Engine stack executor: An error occurred while trying to execute a command: {}.", e.what());
            }
        }
    }
};

} // namespace cmd::details

#endif // _CMD_DETAILS_STACK_EXECUTOR_HPP
