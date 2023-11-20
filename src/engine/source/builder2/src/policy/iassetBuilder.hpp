#ifndef _BUILDDER_POLICY_IASSETBUILDER_HPP
#define _BUILDDER_POLICY_IASSETBUILDER_HPP

#include <store/istore.hpp>

#include "asset.hpp"

namespace builder::policy
{

class IAssetBuilder
{
public:
    virtual ~IAssetBuilder() = default;

    virtual Asset operator()(const store::Doc& document) const = 0;
};

} // namespace builder::policy

#endif // _BUILDDER_POLICY_IASSETBUILDER_HPP
