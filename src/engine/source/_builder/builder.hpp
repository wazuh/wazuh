#ifndef _BUILDER_H
#define _BUILDER_H

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "_builder/environment.hpp"
#include "_builder/json.hpp"
#include "_builder/registry.hpp"


namespace builder
{

template<typename Catalog>
class Builder
{
private:
    // Assert Catalog has a getAsset method
    static_assert(
        std::is_member_function_pointer_v<decltype(&Catalog::getAsset)>,
        "Catalog::getAsset must be a member function");
    // Assert getAsset has expected signature
    // TODO: find a way
    // static_assert(std::is_invocable_r_v<Json,
    //                                     decltype(&Catalog::getAsset),
    //                                     int
    //                                     std::string>,
    //               "Catalog::getAsset must has signature Json(int, string)");

    const Catalog& m_catalog;

public:
    enum AssetType
    {
        Decoder = 0,
        Rule,
        Output,
        Filter,
        Env
    };

    Builder(const Catalog& catalog)
        : m_catalog {catalog}
    {
    }

    Environment buildEnvironment(const std::string& name) const
    {
        auto environment = Environment{name, m_catalog.getAsset(4, name), m_catalog};
        return environment;
    }
};

} // namespace builder

#endif // _BUILDER_H
