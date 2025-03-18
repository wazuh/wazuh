#ifndef _BUILDER_IALLOWEDFIELDS_HPP
#define _BUILDER_IALLOWEDFIELDS_HPP

#include <base/dotPath.hpp>
#include <base/name.hpp>

namespace builder
{

class IAllowedFields
{
public:
    virtual ~IAllowedFields() = default;

    virtual bool check(const base::Name& assetType, const DotPath& field) const = 0;
};
} // namespace builder

#endif // _BUILDER_IALLOWEDFIELDS_HPP
