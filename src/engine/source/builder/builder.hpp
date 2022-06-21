#ifndef _BUILDER_H
#define _BUILDER_H

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "environment.hpp"
#include "registry.hpp"
#include "json.hpp"

namespace builder
{

template<typename Catalog>
class Builder
{
private:
    // // Assert Catalog has a getAsset method
    // static_assert(std::is_member_function_pointer_v<decltype(&Catalog::getAsset)>,
    //               "Catalog::getAsset must be a member function");
    // // Assert getAsset has expected signature
    // // TODO: find a way to static assert the signature
    // // static_assert(std::is_invocable_r_v<Json,
    // //                                     decltype(&Catalog::getAsset),
    // //                                     int
    // //                                     std::string>,
    // //               "Catalog::getAsset must has signature Json(int, string)");

    const Catalog& m_catalog;

    // TODO: Fix catalog to include asset type as a member of Catalog object
    enum class AssetType
    {
        Decoder,
        Rule,
        Output,
        Filter,
        Schema,
        Environment
    };

public:
    Builder(const Catalog& catalog)
        : m_catalog {catalog}
    {
    }

    Environment buildEnvironment(const std::string& name) const
    {
        auto environment = Environment {
            name, json::Json(m_catalog.getAsset("environment", name)), m_catalog};
        return environment;
    }
};

} // namespace builder

#endif // _BUILDER_H
