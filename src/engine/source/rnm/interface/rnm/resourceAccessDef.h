#ifndef RNM_RESOURCE_ACCESS_DEF_HPP
#define RNM_RESOURCE_ACCESS_DEF_HPP

#include <string>

namespace rnm
{
using VSName = std::string;   ///< Virtual Space Name (namespace)
using RoleName = std::string; ///< Role Name

/**
 * @brief Operations that can be performed on a resource of a Virtual Space.
 */
enum class VSOperation
{
    USE,  ///< Use a resources in the Virtual Space.
    READ,  ///< Read a resources in the Virtual Space.
    WRITE, ///< Write a resources in the Virtual Space.
    LIST, ///< List the resources in the Virtual Space.
};

} // namespace name


#endif
