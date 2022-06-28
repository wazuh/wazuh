#ifndef _ASSET_H
#define _ASSET_H

#include <string>
#include <unordered_set>

#include <fmt/format.h>

#include "expression.hpp"
#include "json.hpp"
#include "registry.hpp"

namespace builder
{

class Asset
{
public:
    enum class Type
    {
        DECODER,
        RULE,
        OUTPUT,
        FILTER
    };

    static std::string typeToString(Type type)
    {
        switch (type)
        {
            case Type::DECODER: return "decoder";
            case Type::RULE: return "rule";
            case Type::OUTPUT: return "output";
            case Type::FILTER: return "filter";
            default:
                throw std::runtime_error(
                    fmt::format("[Asset::typeToString(type)] unknown type: [{}]",
                                static_cast<int>(type)));
        }
    }

    std::string m_name;
    base::Expression m_check;
    base::Expression m_stages;
    Type m_type;
    std::unordered_set<std::string> m_parents;
    json::Json m_metadata;

    Asset(std::string name, Type type)
        : m_name {name}
        , m_type {type}
    {
    }

    Asset(const json::Json& jsonDefinition, Type type)
        : m_type {type}
    {
        if (!jsonDefinition.isObject())
        {
            throw std::runtime_error(fmt::format("[Asset::Asset(jsonDefinition, type)] "
                                                 "Asset expects a JSON object, got: [{}]",
                                                 jsonDefinition.typeName()));
        }
        auto objectDefinition = jsonDefinition.getObject().value();

        // Get name
        auto namePos =
            std::find_if(objectDefinition.begin(),
                         objectDefinition.end(),
                         [](auto tuple) { return std::get<0>(tuple) == "name"; });
        if (namePos != objectDefinition.end())
        {
            m_name = std::get<1>(*namePos).getString().value();
            objectDefinition.erase(namePos);
        }
        else
        {
            throw std::runtime_error("[Asset::Asset(jsonDefinition, type)] "
                                     "Asset definition missing name");
        }

        // Get parents
        auto parentsPos = std::find_if(objectDefinition.begin(),
                                       objectDefinition.end(),
                                       [](auto tuple) {
                                           return std::get<0>(tuple) == "parents"
                                                  || std::get<0>(tuple) == "after";
                                       });
        if (parentsPos != objectDefinition.end())
        {
            if (!std::get<1>(*parentsPos).isArray())
            {
                throw std::runtime_error(
                    fmt::format("[Asset::Asset(jsonDefinition, type)] "
                                "Asset definition [parents] expects an array, got: [{}]",
                                std::get<1>(*parentsPos).typeName()));
            }
            auto parents = std::get<1>(*parentsPos).getArray().value();
            for (auto& parent : parents)
            {
                m_parents.insert(parent.getString().value());
            }
            objectDefinition.erase(parentsPos);
        }

        // Get metadata
        auto metadataPos =
            std::find_if(objectDefinition.begin(),
                         objectDefinition.end(),
                         [](auto tuple) { return std::get<0>(tuple) == "metadata"; });
        if (metadataPos != objectDefinition.end())
        {
            m_metadata = std::get<1>(*metadataPos);
            objectDefinition.erase(metadataPos);
        }

        // Get check
        auto checkPos = std::find_if(objectDefinition.begin(),
                                     objectDefinition.end(),
                                     [](auto tuple) {
                                         return std::get<0>(tuple) == "check"
                                                || std::get<0>(tuple) == "allow";
                                     });
        if (checkPos != objectDefinition.end())
        {
            try
            {
                m_check = internals::Registry::getBuilder("stage.check")(
                    {std::get<1>(*checkPos)});
                objectDefinition.erase(checkPos);
            }
            catch (const std::exception& e)
            {
                std::throw_with_nested(
                    std::runtime_error("[Asset::Asset(jsonDefinition, type)] failed to "
                                       "build stage check"));
            }
        }

        // Get stages
        m_stages = base::And::create("stages", {});
        auto asOp = m_stages->getPtr<base::Operation>();
        for (auto& tuple : objectDefinition)
        {
            asOp->getOperands().push_back(internals::Registry::getBuilder(
                "stage." + std::get<0>(tuple))({std::get<1>(tuple)}));
        }
    }

    base::Expression getExpression() const
    {
        base::Expression asset;
        switch (m_type)
        {
            case Type::OUTPUT:
            case Type::RULE:
            case Type::DECODER:
                asset = base::Implication::create(m_name, m_check, m_stages);
                break;
            case Type::FILTER:
                asset = base::And::create(
                    m_name, m_check->getPtr<base::Operation>()->getOperands());
                break;
            default:
                throw std::runtime_error("Unknown asset type in Asset::getExpression");
        }

        return asset;
    }
};

} // namespace builder

#endif // _ASSET_H
