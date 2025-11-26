#include "indexerOutput.hpp"

#include <memory>
#include <regex>
#include <stdexcept>

#include "builders/utils.hpp"
#include <cmstore/categories.hpp>

namespace builder::builders
{

base::Expression indexerOutputBuilder(const json::Json& definition,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx,
                                      const std::weak_ptr<wiconnector::IWIndexerConnector>& iConnector)
{
    if (!definition.isObject())
    {
        throw std::runtime_error(fmt::format(
            "Stage '{}' expects an object but got '{}'", syntax::asset::INDEXER_OUTPUT_KEY, definition.typeName()));
    }

    if (definition.size() != 1)
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects an object with one key but got '{}'",
                                             syntax::asset::INDEXER_OUTPUT_KEY,
                                             definition.size()));
    }

    auto outputObj = definition.getObject().value();

    const auto& [key, value] = *outputObj.begin();
    if (key != syntax::asset::INDEXER_OUTPUT_INDEX_KEY)
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects an object with key '{}' but got '{}'",
                                             syntax::asset::INDEXER_OUTPUT_KEY,
                                             syntax::asset::INDEXER_OUTPUT_INDEX_KEY,
                                             key));
    }

    if (!value.isString())
    {
        throw std::runtime_error(fmt::format("Stage '{}' expects an object with key '{}' to be a string but got '{}'",
                                             syntax::asset::INDEXER_OUTPUT_KEY,
                                             syntax::asset::INDEXER_OUTPUT_INDEX_KEY,
                                             value.typeName()));
    }

    auto indexName = value.getString().value();
    std::optional<std::unordered_map<std::string, std::string>> categoryToIndexMap = std::nullopt;
    // Verify index name, can be auto or part of the valid indexes map
    if (indexName == "auto")
    {
        categoryToIndexMap = cm::store::categories::getMapping();
        if (categoryToIndexMap.value().empty())
        {
            throw std::runtime_error("Error loading categories mapping file. Cannot use 'auto' index.");
        }
    }
    else if (!cm::store::categories::isValidIndex(indexName))
    {
        throw std::runtime_error(fmt::format(
            "Invalid index name '{}'. If not using 'auto' index name must be one of the valid indexes.", indexName));
    }

    auto name = fmt::format("write.output({}/{})", syntax::asset::INDEXER_OUTPUT_KEY, indexName);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> The indexer connector is disabled", name);
    const auto failureTrace2 = fmt::format("{} -> No index associated to category", name);
    const auto failureTrace3 = fmt::format("{} -> Event doesn't have wazuh.category.integration field", name);

    // Get shared ptr
    auto wic = iConnector.lock();
    if (!wic)
    {
        throw std::runtime_error("Indexer connector is not available");
    }

    return base::Term<base::EngineOp>::create(
        name,
        [indexName,
         wic,
         successTrace,
         failureTrace,
         failureTrace2,
         failureTrace3,
         runState = buildCtx->runState(),
         categoryToIndexMap](base::Event event) -> base::result::Result<base::Event>
        {
            auto finalIndexName = indexName;
            if (categoryToIndexMap != std::nullopt)
            {
                // get wazuh.category.integration from event
                auto categoryIntegration = event->getString("/wazuh/category/integration");
                if (!categoryIntegration.has_value())
                {
                    RETURN_FAILURE(runState, event, failureTrace3);
                }

                const auto& categoryKey = categoryIntegration.value();
                if (auto it = categoryToIndexMap.value().find(categoryKey); it != categoryToIndexMap.value().end())
                {
                    finalIndexName = it->second;
                }
                else
                {
                    RETURN_FAILURE(runState, event, failureTrace2);
                }
            }
            // check if present in map, if not throw 3
            wic->index(finalIndexName, event->str());
            RETURN_SUCCESS(runState, event, successTrace);
        });
}

StageBuilder getIndexerOutputBuilder(const std::weak_ptr<wiconnector::IWIndexerConnector>& indexerPtr)
{
    return
        [indexerPtr](const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        return indexerOutputBuilder(definition, buildCtx, indexerPtr);
    };
}

} // namespace builder::builders
