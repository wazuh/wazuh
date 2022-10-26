#ifndef _BUILDER_H
#define _BUILDER_H

#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include <builder/ivalidator.hpp>
#include <json/json.hpp>
#include <name.hpp>
#include <store/istore.hpp>
#include <utils/getExceptionStack.hpp>

#include "asset.hpp"
#include "environment.hpp"
#include "registry.hpp"

namespace builder
{

class Builder : public IValidator
{
private:
    std::shared_ptr<store::IStoreRead> m_storeRead;
    std::shared_ptr<internals::Registry> m_registry;

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
    Builder(std::shared_ptr<store::IStoreRead> storeRead,
            std::shared_ptr<internals::Registry> registry)
        : m_storeRead {storeRead}
        , m_registry {registry}
    {
    }

    Environment buildEnvironment(const base::Name& name) const
    {
        auto envJson = m_storeRead->get(name);
        if (std::holds_alternative<base::Error>(envJson))
        {
            throw std::runtime_error(fmt::format(
                "Engine builder: Environment \"{}\" could not be obtained from the "
                "store: {}.",
                name.fullName(),
                std::get<base::Error>(envJson).message));
        }

        Environment environment {std::get<json::Json>(envJson), m_storeRead, m_registry};

        return environment;
    }

    std::optional<base::Error> validateEnvironment(const json::Json& json) const override
    {
        try
        {
            Environment env {json, m_storeRead, m_registry};
            env.getExpression();
        }
        catch (const std::exception& e)
        {
            return base::Error {utils::getExceptionStack(e)};
        }

        return std::nullopt;
    }

    std::optional<base::Error> validateAsset(const json::Json& json) const override
    {
        try
        {
            // TODO: Remove asset type in Asset
            Asset asset {json, Asset::Type::DECODER, m_registry};
            asset.getExpression();
        }
        catch (const std::exception& e)
        {
            return base::Error {utils::getExceptionStack(e)};
        }

        return std::nullopt;
    }
};

} // namespace builder

#endif // _BUILDER_H
