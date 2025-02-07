#include "indexerOutput.hpp"

#include <memory>
#include <stdexcept>

#include "builders/utils.hpp"

namespace builder::builders
{

base::Expression indexerOutputBuilder(const json::Json& definition,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx,
                                      const std::shared_ptr<IIndexerConnector>& iConnector)
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

    auto name = fmt::format("write.output({}/{})", syntax::asset::INDEXER_OUTPUT_KEY, indexName);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> The indexer connector is disabled", name);

    return base::Term<base::EngineOp>::create(
        name,
        [indexName, iConnector, successTrace, failureTrace, runState = buildCtx->runState()](
            base::Event event) -> base::result::Result<base::Event>
        {
            if (!iConnector)
            {
                RETURN_FAILURE(runState, event, failureTrace);
            }

            const auto pushEvent =
                fmt::format(R"({{"operation": "ADD", "index": "{}", "data": {} }})", indexName, event->str());
            iConnector->publish(pushEvent);

            RETURN_SUCCESS(runState, event, successTrace);
        });
}

StageBuilder getIndexerOutputBuilder(const std::shared_ptr<IIndexerConnector>& indexerPtr)
{
    return
        [indexerPtr](const json::Json& definition, const std::shared_ptr<const IBuildCtx>& buildCtx) -> base::Expression
    {
        return indexerOutputBuilder(definition, buildCtx, indexerPtr);
    };
}

} // namespace builder::builders
