#ifndef _BUILDER_H
#define _BUILDER_H

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <name.hpp>
#include <store/istore.hpp>

#include "environment.hpp"
#include "registry.hpp"
#include <json/json.hpp>

namespace builder
{

class Builder
{
private:
    std::shared_ptr<store::IStoreRead> m_storeRead;

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
    Builder(std::shared_ptr<store::IStoreRead> storeRead)
        : m_storeRead {storeRead}
    {
    }

    Environment buildEnvironment(const base::Name& name) const
    {
        auto envJson = m_storeRead->get(name);
        if (std::holds_alternative<base::Error>(envJson))
        {
            throw std::runtime_error(fmt::format(
                "[Environment] Error retreiving environment [{}] from store: {}",
                name.fullName(),
                std::get<base::Error>(envJson).message));
        }

        auto environment =
            Environment {name.fullName(), std::get<json::Json>(envJson), m_storeRead};

        return environment;
    }
};

} // namespace builder

#endif // _BUILDER_H
