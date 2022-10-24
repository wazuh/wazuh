#include "asset.hpp"

#include <fmt/format.h>

#include "definitions.hpp"
#include "registry.hpp"

namespace builder
{
std::string Asset::typeToString(Asset::Type type)
{
    switch (type)
    {
        case Asset::Type::DECODER: return "decoder";
        case Asset::Type::RULE: return "rule";
        case Asset::Type::OUTPUT: return "output";
        case Asset::Type::FILTER: return "filter";
        default:
            throw std::runtime_error(
                fmt::format("[Asset::typeToString(type)] unknown type: [{}]",
                            static_cast<int>(type)));
    }
}

Asset::Asset(std::string name, Asset::Type type)
    : m_name {name}
    , m_type {type}
{
}

Asset::Asset(const json::Json& jsonDefinition, Asset::Type type)
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
    auto namePos = std::find_if(objectDefinition.begin(),
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
            m_check =
                internals::Registry::getBuilder("stage.check")({std::get<1>(*checkPos)});
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
            auto parseExpression =
                internals::Registry::getBuilder("stage.parse")({std::get<1>(*parsePos)});
            objectDefinition.erase(parsePos);
            if (m_check)
            {
                m_check = base::And::create("condition", {m_check, parseExpression});
            }
            else
            {
                m_check = parseExpression;
            }
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

base::Expression Asset::getExpression() const
{
    base::Expression asset;
    switch (m_type)
    {
        case Asset::Type::OUTPUT:
        case Asset::Type::RULE:
        case Asset::Type::DECODER:
            if (m_check)
            {
                asset = base::Implication::create(m_name, m_check, m_stages);
            }
            else
            {
                auto trueExpression = base::Term<base::EngineOp>::create(
                    "AcceptAll",
                    [](auto e) { return base::result::makeSuccess(e, "AcceptAll"); });
                asset = base::Implication::create(m_name, trueExpression, m_stages);
            }
            break;
        case Asset::Type::FILTER: asset = base::And::create(m_name, {m_check}); break;
        default: throw std::runtime_error("Unknown asset type in Asset::getExpression");
    }

    return asset;
}

} // namespace builder
