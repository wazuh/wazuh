#ifndef _BASE_ERROR_HPP
#define _BASE_ERROR_HPP

#include <string>

namespace base
{
/**
 * @brief The Error struct
 *
 * The Error struct is used to represent an error string in the Engine.
 * !note This struct is needed to desambiguate between a content string and an Error
 * string on variants.
 *
 */
struct Error
{
    std::string message; ///< Error message
};

} // namespace base

#endif // _BASE_ERROR_HPP
