#ifndef _ASSET_H
#define _ASSET_H

#include <string>
#include <unordered_set>

#include <fmt/format.h>

#include "_builder/expression.hpp"
#include "_builder/json.hpp"
#include "_builder/registry.hpp"

class Asset
{
public:
    enum class Type
    {
        DECODER,
        FILTER,
        RULE,
        OUTPUT
    };

    std::string m_name;
    Expression m_check;
    Expression m_stages;
    Type m_type;
    std::unordered_set<std::string> m_parents;
    Json m_metadata;

    Asset(std::string name, Type type)
        : m_name {name}
        , m_type {type}
    {
    }

    Asset(const Json& jsonDefinition, Type type)
        : m_type {type}
    {
        auto objectDefinition = jsonDefinition.getObject();

        // Get name
        auto namePos = std::find_if(objectDefinition.begin(),
                                    objectDefinition.end(),
                                    [](auto tuple)
                                    { return std::get<0>(tuple) == "name"; });
        if (namePos != objectDefinition.end())
        {
            m_name = std::get<1>(*namePos).getString();
            objectDefinition.erase(namePos);
        }
        else
        {
            throw std::runtime_error("Asset definition must have a name");
        }

        // Get parents
        auto parentsPos = std::find_if(
            objectDefinition.begin(),
            objectDefinition.end(),
            [](auto tuple) { return std::get<0>(tuple) == "parents"; });
        if (parentsPos != objectDefinition.end())
        {
            auto parents = std::get<1>(*parentsPos).getArray();
            for (auto& parent : parents)
            {
                m_parents.insert(parent.getString());
            }
            objectDefinition.erase(parentsPos);
        }

        // Get metadata
        auto metadataPos = std::find_if(
            objectDefinition.begin(),
            objectDefinition.end(),
            [](auto tuple) { return std::get<0>(tuple) == "metaData"; });
        if (metadataPos != objectDefinition.end())
        {
            m_metadata = std::get<1>(*metadataPos);
            objectDefinition.erase(metadataPos);
        }

        // Get check
        auto checkPos = std::find_if(objectDefinition.begin(),
                                     objectDefinition.end(),
                                     [](auto tuple)
                                     { return std::get<0>(tuple) == "check"; });
        if (checkPos != objectDefinition.end())
        {
            m_check =
                Registry::getBuilder("stage.check")({std::get<1>(*checkPos)});
            objectDefinition.erase(checkPos);
        }

        // Get stages
        m_stages = And::create("stages", {});
        auto asOp = m_stages->getPtr<Operation>();
        for (auto& tuple : objectDefinition)
        {
            asOp->getOperands().push_back(Registry::getBuilder(
                "stage." + std::get<0>(tuple))({std::get<1>(tuple)}));
        }
    }

    Expression getExpression() const
    {
        Expression asset;
        switch (m_type)
        {
            case Type::OUTPUT:
            case Type::RULE:
            case Type::DECODER:
                asset = Implication::create(m_name, m_check, m_stages);
                break;
            case Type::FILTER:
                asset = And::create(
                    m_name, m_check->getPtr<Operation>()->getOperands());
                break;
            default:
                throw std::runtime_error(
                    "Unknown asset type in Asset::getExpression");
        }

        return asset;
    }
};

#endif // _ASSET_H
