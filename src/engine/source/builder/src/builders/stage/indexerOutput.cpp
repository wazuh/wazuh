#include "indexerOutput.hpp"

#include <memory>
#include <regex>
#include <stdexcept>

#include "builders/utils.hpp"

namespace builder::builders
{

namespace
{

// lowercase field conversion and spaces replacement with hyphens
auto sanitizeField = [](const std::string& field, base::Event event) -> std::string
{
    auto fieldValue = event->getString(field);
    if (fieldValue == std::nullopt)
    {
        throw std::runtime_error(
            fmt::format("Field '{}' does not exist in the event", field));
    }
    auto fieldString = fieldValue.value();
    std::transform(fieldString.begin(),
                   fieldString.end(),
                   fieldString.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    std::replace(fieldString.begin(), fieldString.end(), ' ', '-');
    return fieldString;
};

} // namespace

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

    // Extract placeHolders and reformat json dot path from input string
    std::vector<std::string> placeholderVec;
    std::regex placeholder_regex(R"(\$\{([^}]+)\})");
    auto words_begin = std::sregex_iterator(indexName.begin(), indexName.end(), placeholder_regex);
    auto words_end = std::sregex_iterator();

    for (std::sregex_iterator i = words_begin; i != words_end; ++i)
    {
        placeholderVec.push_back(json::Json::formatJsonPath((*i)[1].str()));
    }

    const auto prefix = "wazuh-events-v5";
    if (placeholderVec.empty())
    {
        if (!base::utils::string::startsWith(indexName, prefix))
        {
            throw std::runtime_error(
                fmt::format("Stage '{}' expects the index name to start with 'wazuh-events-v5-' but got '{}'",
                            syntax::asset::INDEXER_OUTPUT_KEY,
                            indexName));
        }
    }

    auto name = fmt::format("write.output({}/{})", syntax::asset::INDEXER_OUTPUT_KEY, indexName);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> The indexer connector is disabled", name);
    const auto failureTrace2 = fmt::format("{} -> Couldn't get field {} from event", name, "{}");

    // Get shared ptr
    auto wic = iConnector.lock();
    if (!wic)
    {
        throw std::runtime_error("Indexer connector is not available");
    }

    return base::Term<base::EngineOp>::create(
        name,
        [indexName,
         placeholderVec,
         wic,
         successTrace,
         failureTrace,
         failureTrace2,
         sanitizeField,
         prefix,
         runState = buildCtx->runState()](base::Event event) -> base::result::Result<base::Event>
        {
            std::string finalIndexName;

            for (auto& field : placeholderVec)
            {
                try
                {
                    finalIndexName += std::string("-") + sanitizeField(field, event);
                }
                catch(const std::exception& e)
                {
                    RETURN_FAILURE(runState, event, fmt::format(failureTrace2, field));
                }
            }

            try
            {
                wic->index(finalIndexName.empty() ? indexName : prefix + finalIndexName, event->str());
            }
            catch (const std::exception& e)
            {
                RETURN_FAILURE(runState, event, failureTrace);
            }

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
