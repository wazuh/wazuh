#ifndef _STACK_EXECUTOR_HPP
#define _STACK_EXECUTOR_HPP

#include <deque>
#include <functional>

namespace cmd
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
    void add(std::function<void()> func);

    /**
     * @brief Execute the stack of functions.
     *
     * The functions are executed in reverse order of insertion (LIFO), and the stack is
     * cleared.
     */
    void execute();
};

} // namespace cmd

#endif // _STACK_EXECUTOR_HPP