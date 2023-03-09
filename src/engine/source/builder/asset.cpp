#include "asset.hpp"

#include <fmt/format.h>
#include <logging/logging.hpp>

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
        default: throw std::runtime_error(fmt::format("Asset type ('{}') unknown", static_cast<int>(type)));
    }
}

Asset::Asset(std::string name, Asset::Type type)
    : m_name {name}
    , m_type {type}
{
}

Asset::Asset(const json::Json& jsonDefinition,
             Asset::Type type,
             std::shared_ptr<internals::Registry> registry)
    : m_type {type}
{
    if (!jsonDefinition.isObject())
    {
        LOG_DEBUG("Engine assets: '{}' method: JSON definition: '{}'.", __func__, jsonDefinition.str());
        throw std::runtime_error(fmt::format(
            "The asset should be an object, but it is of type '{}'. Thus, the asset 'name' field could not be obtained",
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
        LOG_DEBUG("Engine assets: '{}' method: JSON definition: '{}'.", __func__, jsonDefinition.str());
        if (objectDefinition.end() != namePos && !std::get<1>(*namePos).isString())
        {
            throw std::runtime_error(fmt::format("Asset 'name' field is not a string"));
        }
        throw std::runtime_error(fmt::format("Asset 'name' field is missing"));
    }

    const std::string assetName {tmpJson.getString("/name").value_or("")};

    // Get parents
    auto sourcesPos = std::find_if(objectDefinition.begin(),
                                   objectDefinition.end(),
                                   [](auto tuple) {
                                       return std::get<0>(tuple) == "sources"
                                              || std::get<0>(tuple) == "after";
                                   });
    if (objectDefinition.end() != sourcesPos)
    {
        if (!std::get<1>(*sourcesPos).isArray())
        {
            LOG_DEBUG("Engine assets: '{}' method: JSON definition: '{}'.", __func__, jsonDefinition.str());
            throw std::runtime_error(
                fmt::format("Asset '{}' sources definition is expected to be an array but it is of type '{}'",
                            assetName,
                            std::get<1>(*sourcesPos).typeName()));
        }
        auto sources = std::get<1>(*sourcesPos).getArray().value();
        for (auto& source : sources)
        {
            m_parents.insert(source.getString().value());
        }
        objectDefinition.erase(sourcesPos);
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
            m_check = registry->getBuilder("stage.check")({std::get<1>(*checkPos)});
            objectDefinition.erase(checkPos);
        }
        catch (const std::exception& e)
        {
            LOG_DEBUG("Engine assets: '{}' method: JSON definition: '{}'.", __func__, jsonDefinition.str());
            throw std::runtime_error(
                fmt::format("The check stage failed while building the asset '{}': {}", assetName, e.what()));
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
                registry->getBuilder("stage.parse")({std::get<1>(*parsePos)});
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
            throw std::runtime_error(fmt::format("Parse stage: Building asset '{}' failed: {}", assetName, e.what()));
        }
    }

    // Get stages
    m_stages = base::And::create("stages", {});
    auto asOp = m_stages->getPtr<base::Operation>();
    for (auto& tuple : objectDefinition)
    {
        auto stageName = "stage." + std::get<0>(tuple);
        auto stageDefinition = std::get<1>(tuple);
        auto stageExpression = registry->getBuilder(stageName)({stageDefinition});
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
        default: throw std::runtime_error(fmt::format("Asset type not supported from asset '{}'", m_name));
    }

    return asset;
}

} // namespace builder
