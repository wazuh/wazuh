#ifndef _BUILDER_IALLOWEDFIELDS_HPP
#define _BUILDER_IALLOWEDFIELDS_HPP

#include <base/dotPath.hpp>
#include <base/name.hpp>

namespace builder
{

/**
 * @brief Interface for checking if a field is allowed to be modified for a given asset type.
 *
 */
class IAllowedFields
{
public:
    virtual ~IAllowedFields() = default;

    /**
     * @brief Check if a field is allowed to be modified for a given asset type.
     *
     * @param assetType The asset type.
     * @param field The field to check.
     * @return true if the field is allowed to be modified, false otherwise.
     */
    virtual bool check(const base::Name& assetType, const DotPath& field) const = 0;
};
} // namespace builder

#endif // _BUILDER_IALLOWEDFIELDS_HPP
