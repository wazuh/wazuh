#include "assetBuilder.hpp"

#include <base/utils/stringUtils.hpp>
#include <fmt/format.h>

#include "syntax.hpp"

namespace builder::policy
{
base::Name AssetBuilder::getName(const json::Json& value) const
{
    auto resp = value.getString();
    if (!resp)
    {
        throw std::runtime_error(
            fmt::format("Expected '{}' to be a 'string' but got '{}'", syntax::asset::NAME_KEY, value.typeName()));
    }
    base::Name name;
    try
    {
        name = base::Name(resp.value());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Invalid name '{}': {}", resp.value(), e.what()));
    }

    return name;
}

std::vector<base::Name> AssetBuilder::getParents(const json::Json& value) const
{
    auto resp = value.getArray();
    if (!resp)
    {
        throw std::runtime_error(
            fmt::format("Expected '{}' to be an 'array' but got '{}'", syntax::asset::PARENTS_KEY, value.typeName()));
    }
    std::vector<base::Name> parents;
    for (const auto& jParent : resp.value())
    {
        // Check for string
        auto parentStr = jParent.getString();
        if (!parentStr)
        {
            throw std::runtime_error(
                fmt::format("Found non-string value '{}' in '{}'", jParent.typeName(), syntax::asset::PARENTS_KEY));
        }

        // Parse name
        base::Name parentName;
        try
        {
            parentName = base::Name(parentStr.value());
        }
        catch (const std::exception& e)
        {
            throw std::runtime_error(fmt::format("Invalid parent name '{}': {}", parentStr.value(), e.what()));
        }

        // TODO : check parent is the same type as the asset??
        // if (parentName.parts().front() != name.parts().front()) -> error

        // Check for duplicates
        if (std::find(parents.begin(), parents.end(), parentName) != parents.end())
        {
            throw std::runtime_error(fmt::format("Parent '{}' is duplicated", parentName));
        }
        parents.push_back(parentName);
    }

    return parents;
}

base::Expression AssetBuilder::buildExpression(const base::Name& name,
                                               std::vector<std::tuple<std::string, json::Json>>& objDoc) const
{
    auto newContext = std::make_shared<builders::BuildCtx>(*m_buildCtx);

    // Get definitions (optional, may appear anywhere in the asset)
    auto definitionsPos = std::find_if(
        objDoc.begin(), objDoc.end(), [](auto tuple) { return std::get<0>(tuple) == syntax::asset::DEFINITIONS_KEY; });
    if (objDoc.end() != definitionsPos)
    {
        auto definitions = m_definitionsBuilder->build(std::get<1>(*definitionsPos));
        newContext->setDefinitions(definitions);
        objDoc.erase(definitionsPos);
    }
    else
    {
        // Empty definitions
        json::Json emptyDefinitions;
        emptyDefinitions.setObject();
        newContext->setDefinitions(m_definitionsBuilder->build(std::move(emptyDefinitions)));
    }

    // Build condition expression
    std::vector<base::Expression> conditionExpressions;
    base::Expression condition;

    // Check stage
    if (!objDoc.empty())
    {
        {
            const auto& [key, value] = *objDoc.begin();
            if (key == syntax::asset::CHECK_KEY)
            {
                auto resp = m_buildCtx->registry().get<builders::StageBuilder>(key);
                if (base::isError(resp))
                {
                    throw std::runtime_error(fmt::format("Could not find builder for stage '{}'", key));
                }
                auto builder = base::getResponse<builders::StageBuilder>(resp);
                auto check = builder(value, newContext);
                conditionExpressions.emplace_back(std::move(check));
                objDoc.erase(objDoc.begin());
            }
        }

        // Parse stage
        {
            const auto& [key, value] = *objDoc.begin();
            size_t keySize = strlen(syntax::asset::PARSE_KEY);
            // Parse stage syntax is different from other stages parse|<key>: <value>
            if (key.compare(0, keySize, syntax::asset::PARSE_KEY) == 0)
            {
                // TODO fix this hack, we need to format the json as the old parse stage

                bool meetsFormat = key.length() > keySize && key[keySize] == '|';

                if (!meetsFormat)
                {
                    throw std::runtime_error("Stage parse: needs the character '|' to indicate the field");
                }

                // Extract text after '|'
                auto targetField = key.substr(keySize + 1);

                try
                {
                    DotPath {targetField};
                }
                catch (const std::exception& e)
                {
                    throw std::runtime_error(fmt::format("Stage parse: Could not get field: {}", e.what()));
                }

                json::Json stageParseValue;
                stageParseValue.setArray();
                if (value.isArray())
                {
                    json::Json tmp;
                    tmp.setObject();
                    auto arr = value.getArray().value();
                    for (size_t i = 0; i < arr.size(); i++)
                    {
                        auto parseValue = arr[i].getString().value();
                        tmp.setString(parseValue, json::Json::formatJsonPath(targetField, true));
                        stageParseValue.appendJson(tmp);
                    }
                }

                auto resp = m_buildCtx->registry().get<builders::StageBuilder>(syntax::asset::PARSE_KEY);
                if (base::isError(resp))
                {
                    throw std::runtime_error(fmt::format("Could not find builder for stage '{}'", key));
                }
                auto builder = base::getResponse<builders::StageBuilder>(resp);
                auto parse = builder(stageParseValue, newContext);
                conditionExpressions.emplace_back(std::move(parse));
                objDoc.erase(objDoc.begin());
            }
        }
    }

    // FIXME: The SUCCESS trace message is needed so test can parse if an asset succeeded or not
    conditionExpressions.emplace_back(base::Term<base::EngineOp>::create(
        "AcceptAll", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); }));

    condition = base::And::create(syntax::asset::CONDITION_NAME, std::move(conditionExpressions));

    // Build the consequence expression (rest of stages)
    std::vector<base::Expression> consequenceExpressions;
    base::Expression consequence;

    for (const auto [key, value] : objDoc)
    {
        auto resp = m_buildCtx->registry().get<builders::StageBuilder>(key);
        if (base::isError(resp))
        {
            throw std::runtime_error(fmt::format("Could not find builder for stage '{}'", key));
        }
        auto builder = base::getResponse<builders::StageBuilder>(resp);
        auto consequence = builder(value, newContext);
        consequenceExpressions.emplace_back(std::move(consequence));
    }

    if (consequenceExpressions.empty())
    {
        return base::And::create(name, {std::move(condition)});
    }

    // Delete variables from the event when asset is executed (TODO: Find a better way to manage variables)
    {
        auto ifVar = [](const std::string& attr) -> bool
        {
            return !attr.empty() && attr[0] == syntax::field::VAR_ANCHOR;
        };
        auto deleteVariables = base::Term<base::EngineOp>::create("DeleteVariables",
                                                                  [ifVar](auto e)
                                                                  {
                                                                      e->eraseIfKey(ifVar);
                                                                      return base::result::makeSuccess(e, "");
                                                                  });
        consequenceExpressions.emplace_back(std::move(deleteVariables));
    }

    consequence = base::And::create(syntax::asset::CONSEQUENCE_NAME, std::move(consequenceExpressions));

    return base::Implication::create(name, std::move(condition), std::move(consequence));
}

Asset AssetBuilder::operator()(const store::Doc& document) const
{
    // Check document is an object
    auto objDocOpt = document.getObject();
    if (!objDocOpt)
    {
        throw std::runtime_error("Document is not an object");
    }

    if (objDocOpt.value().empty())
    {
        throw std::runtime_error("Document is empty");
    }

    // We need to copy the document because we need to iterate and remove
    // fixed order stages name->metadata->parents->check->stages
    auto objDoc = objDocOpt.value();

    // Get name
    base::Name name;
    {
        const auto& [key, value] = *objDoc.begin();
        if (key != syntax::asset::NAME_KEY)
        {
            throw std::runtime_error(
                fmt::format("Expected '{}' key in asset document but got '{}'", syntax::asset::NAME_KEY, key));
        }
        name = getName(value);
        objDoc.erase(objDoc.begin());
    }

    // Get metadata (optional)
    json::Json metadata;
    {
        const auto& [key, value] = *objDoc.begin();
        if (key == syntax::asset::METADATA_KEY)
        {
            // TODO: Implement
            objDoc.erase(objDoc.begin());
        }
    }

    // Get parents (optional)
    std::vector<base::Name> parents;
    {
        const auto& [key, value] = *objDoc.begin();
        if (key == syntax::asset::PARENTS_KEY)
        {
            parents = getParents(value);
            objDoc.erase(objDoc.begin());
        }
    }

    // Build the expression (rest of keys if any)
    auto expression = buildExpression(name, objDoc);

    return Asset {std::move(name), std::move(expression), std::move(parents)};
}

} // namespace builder::policy
