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
auto sanitizeField = [](const std::string& field, const base::Event& event) -> std::string
{
    auto fieldValue = event->getString(field);
    if (fieldValue == std::nullopt)
    {
        throw std::runtime_error(fmt::format("Field '{}' does not exist in the event", field));
    }
    auto fieldString = fieldValue.value();
    std::transform(
        fieldString.begin(), fieldString.end(), fieldString.begin(), [](unsigned char c) { return std::tolower(c); });
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

    // Index name can’t contain any of the following characters:
    // ' ', ',', ':', '"', '*', '+', '/', '\', '|', '?', '#', '>', or '<'
    if (!std::regex_match(indexName, std::regex(R"(^wazuh-events-v5-(?:[a-z0-9.-]+|\$\{[^}]+\})*$)")))
    {
        throw std::runtime_error(
            fmt::format("Stage '{}' expects the index name to start with 'wazuh-events-v5-' and it should only contain "
                        "lowercase letters, numbers, dots, hyphens, or placeholders but got '{}'",
                        syntax::asset::INDEXER_OUTPUT_KEY,
                        indexName));
    }

    // Extract placeholders and drop in map
    std::map<std::string, std::string> placeholderMap;
    std::regex placeholder_regex(R"(\$\{([^}]+)\})");
    auto words_begin = std::sregex_iterator(indexName.begin(), indexName.end(), placeholder_regex);
    auto words_end = std::sregex_iterator();
    for (std::sregex_iterator i = words_begin; i != words_end; ++i)
    {
        std::string fullMatch = (*i)[0].str();
        std::string formattedPath = json::Json::formatJsonPath((*i)[1].str());
        placeholderMap[fullMatch] = formattedPath;
    }

    auto name = fmt::format("write.output({}/{})", syntax::asset::INDEXER_OUTPUT_KEY, indexName);
    const auto successTrace = fmt::format("{} -> Success", name);
    const auto failureTrace = fmt::format("{} -> The indexer connector is disabled", name);
    const auto failureTrace2 = fmt::format("{} -> Couldn't get field {} from event", name, "{}");
    const auto failureTrace3 = fmt::format("{} -> Index name '{}' exceeds 255 characters limit", name, "{}");

    // Get shared ptr
    auto wic = iConnector.lock();
    if (!wic)
    {
        throw std::runtime_error("Indexer connector is not available");
    }

    return base::Term<base::EngineOp>::create(
        name,
        [indexName,
         placeholderMap,
         wic,
         successTrace,
         failureTrace,
         failureTrace2,
         failureTrace3,
         sanitizeField,
         runState = buildCtx->runState()](base::Event event) -> base::result::Result<base::Event>
        {
            std::string finalIndexName = indexName;
            for (const auto& [placeholder, jsonPath] : placeholderMap)
            {
                try
                {
                    std::string sanitized = sanitizeField(jsonPath, event);
                    // Replace all occurrences of the placeholder in the indexName
                    size_t pos = 0;
                    while ((pos = finalIndexName.find(placeholder, pos)) != std::string::npos)
                    {
                        finalIndexName.replace(pos, placeholder.length(), sanitized);
                        pos += sanitized.length();
                    }
                }
                catch (const std::exception& e)
                {
                    RETURN_FAILURE(runState, event, fmt::format(failureTrace2, jsonPath));
                }
            }

            if (finalIndexName.size() > 255)
            {
                RETURN_FAILURE(runState, event, fmt::format(failureTrace3, finalIndexName));
            }

            try
            {
                wic->index(finalIndexName, event->str());
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
