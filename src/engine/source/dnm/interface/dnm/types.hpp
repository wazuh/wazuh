#ifndef DNM_TYPES_HPP
#define DNM_TYPES_HPP

#include <string>

namespace dnm
{
using NamespaceID = std::string; ///< Namespace identifier

/**
 * @brief Key Type
 */
enum class KeyType
{
    DOCUMENT,   ///< Document
    COLLECTION, ///< Collection
};
} // namespace dnm

#endif // DNM_TYPES_HPP
