#ifndef _ASSET_H
#define _ASSET_H

#include <string>
#include <unordered_set>

#include <fmt/format.h>

#include "definitions.hpp"
#include "expression.hpp"
#include "json.hpp"
#include "registry.hpp"

namespace builder
{

/**
 * @brief Intermediate representation of the Asset.
 *
 * The Asset contains the following information:
 * - The name of the asset.
 * - The type of the asset (decoder, rule, output, filter).
 * - The list of parents of the asset, stored in a set.
 * - Metadata about the asset, as a JSON object.
 * - The expression of the check part (check, parse) of the asset.
 * - The expression of the rest of stages in the asset.
 *
 * @warning Stages check and parse are builded first in said order, ignoring the
 * order in the JSON object.
 */
class Asset
{
public:
    /**
     * @brief Type of Asset.
     *
     */
    enum class Type
    {
        DECODER,
        RULE,
        OUTPUT,
        FILTER
    };

    /**
     * @brief Get the type name.
     *
     * @param type
     * @return std::string
     * @throws std::runtime_error if the type is unknown.
     */
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

    /**
     * @brief Construct a new Empty Asset object
     *
     * @param name Name of the asset.
     * @param type Type of the asset.
     */
    Asset(std::string name, Type type)
        : m_name {name}
        , m_type {type}
    {
    }

    /**
     * @brief Construct a new Asset object from a JSON object.
     *
     * @warning Stages check and parse are builded first in said order, ignoring the order
     * in the JSON object.
     *
     * @param jsonDefinition JSON object containing the definition of the asset.
     * @param type Type of the asset.
     * @throws std::runtime_error if the Asset could not be constructed.
     */
    Asset(const json::Json& jsonDefinition, Type type)
        : m_type {type}
    {
        if (!jsonDefinition.isObject())
        {
            throw std::runtime_error(fmt::format("[Asset::Asset(jsonDefinition, type)] "
                                                 "Asset expects a JSON object, got: [{}]",
                                                 jsonDefinition.typeName()));
        }
        // Process definitions
        json::Json tmpJson {jsonDefinition};
        internals::substituteDefinitions(tmpJson);

        auto objectDefinition = tmpJson.getObject().value();

        // Get name
        auto namePos =
            std::find_if(objectDefinition.begin(),
                         objectDefinition.end(),
                         [](auto tuple) { return std::get<0>(tuple) == "name"; });
        if (objectDefinition.end() != namePos && std::get<1>(*namePos).isString())
        {
            m_name = std::get<1>(*namePos).getString().value();
            objectDefinition.erase(namePos);
        }
        else
        {
            throw std::runtime_error("[Asset::Asset(jsonDefinition, type)] "
                                     "Asset definition missing string name");
        }

        // Get parents
        auto parentsPos = std::find_if(objectDefinition.begin(),
                                       objectDefinition.end(),
                                       [](auto tuple) {
                                           return std::get<0>(tuple) == "parents"
                                                  || std::get<0>(tuple) == "after";
                                       });
        if (objectDefinition.end() != parentsPos)
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
        if (objectDefinition.end() != metadataPos)
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
        if (objectDefinition.end() != checkPos)
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

        // Get parse if present
        auto parsePos =
            std::find_if(objectDefinition.begin(),
                         objectDefinition.end(),
                         [](auto tuple) { return std::get<0>(tuple) == "parse"; });
        if (objectDefinition.end() != parsePos)
        {
            try
            {
                auto parseExpression = internals::Registry::getBuilder("stage.parse")(
                    {std::get<1>(*parsePos)});
                objectDefinition.erase(parsePos);
                m_check = base::And::create("condition", {m_check, parseExpression});
            }
            catch (const std::exception& e)
            {
                std::throw_with_nested(
                    std::runtime_error("[Asset::Asset(jsonDefinition, type)] failed to "
                                       "build stage parse"));
            }
        }

        // Get stages
        m_stages = base::And::create("stages", {});
        auto asOp = m_stages->getPtr<base::Operation>();
        for (auto& tuple : objectDefinition)
        {
            auto stageName = "stage." + std::get<0>(tuple);
            auto stageDefinition = std::get<1>(tuple);
            auto stageExpression =
                internals::Registry::getBuilder(stageName)({stageDefinition});
            asOp->getOperands().push_back(stageExpression);
        }
    }

    /**
     * @brief Get the Expression object of the Asset.
     *
     * @return base::Expression
     * @throws std::runtime_error if the Expression could not be constructed.
     */
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
            case Type::FILTER: asset = base::And::create(m_name, {m_check}); break;
            default:
                throw std::runtime_error("Unknown asset type in Asset::getExpression");
        }

        return asset;
    }
};

} // namespace builder

#endif // _ASSET_H
