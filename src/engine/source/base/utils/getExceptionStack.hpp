#ifndef _GET_EXCEPTION_STACK_HPP
#define _GET_EXCEPTION_STACK_HPP

#include <exception>
#include <sstream>
#include <string>

namespace utils
{
/**
 * @brief Get the exception stack as a string.
 *
 * @param e Exception to get the stack from.
 * @param level Level of the exception to get the stack from.
 * @return String with the exception stack.
 */
inline std::string getExceptionStack(const std::exception& e, int level = 0)
{
    std::stringstream ss;
    // TODO: is the level necessary?
    ss << std::string(level, ' ') << e.what();
    try
    {
        std::rethrow_if_nested(e);
    }
    catch (const std::exception& nestedException)
    {
        ss << getExceptionStack(nestedException, level + 1);
    }

    return ss.str();
}
} // namespace utils

#endif // _GET_EXCEPTION_STACK_HPP
