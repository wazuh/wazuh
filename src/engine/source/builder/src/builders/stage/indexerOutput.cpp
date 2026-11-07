// SPDX-License-Identifier: AGPL-3.0-or-later
#include "indexerOutput.hpp"

#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string_view>

#include "builders/utils.hpp"

namespace builder::builders
{

namespace
{
constexpr std::string_view INDEX_PREFIX = "wazuh-events-v5-";

/**
 * @brief Parses an index name of the form wazuh-events-v5-(?:[a-z0-9.-]+|\$\{[^}]+\})*
 *
 * Linear scan instead of std::regex: libstdc++'s regex recurses per character, so an unbounded name overflows the
 * stack.
 *
 * @return Map of each placeholder (`${field}`) to its field path, or nullopt if the name is invalid.
 */
std::optional<std::map<std::string, std::string>> parseIndexName(std::string_view indexName)
{
    if (indexName.substr(0, INDEX_PREFIX.size()) != INDEX_PREFIX)
    {
        return std::nullopt;
    }

    std::map<std::string, std::string> placeholders;
    size_t pos = INDEX_PREFIX.size();
    while (pos < indexName.size())
    {
        const char c = indexName[pos];
        if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-')
        {
            ++pos;
            continue;
        }

        // Placeholder: '${' + at least one non-'}' character + '}'
        if (indexName.substr(pos, 2) != "${")
        {
            return std::nullopt;
        }
        const auto close = indexName.find('}', pos + 2);
        if (close == std::string_view::npos || close == pos + 2)
        {
            return std::nullopt;
        }
        placeholders.emplace(std::string(indexName.substr(pos, close - pos + 1)),
                             std::string(indexName.substr(pos + 2, close - pos - 2)));
        pos = close + 1;
    }

    return placeholders;
}
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

    auto indexName = std::string {};
    if (value.getString(indexName) != json::RetGet::Success || indexName.empty())
    {
        throw std::runtime_error(
            fmt::format("Stage '{}' expects an object with key '{}' to be a non-empty string but got '{}'",
                        syntax::asset::INDEXER_OUTPUT_KEY,
                        syntax::asset::INDEXER_OUTPUT_INDEX_KEY,
                        value.typeName()));
    }

    // Index name can’t contain any of the following characters:
    // ' ', ',', ':', '"', '*', '+', '/', '\', '|', '?', '#', '>', or '<'
    auto parsedPlaceholders = parseIndexName(indexName);
    if (!parsedPlaceholders)
    {
        throw std::runtime_error(
            fmt::format("Stage '{}' expects the index name to start with 'wazuh-events-v5-' and it should only contain "
                        "lowercase letters, numbers, dots, hyphens, or placeholders but got '{}'",
                        syntax::asset::INDEXER_OUTPUT_KEY,
                        indexName));
    }

    // Extract placeholders and drop in map
    std::map<std::string, std::string> placeholderMap;
    for (const auto& [fullMatch, field] : *parsedPlaceholders)
    {
        placeholderMap[fullMatch] = json::Json::formatJsonPath(field);
    }

    // Pre-build PointerPath objects for each placeholder to avoid re-parsing per event
    std::vector<std::pair<std::string, json::PointerPath>> placeholderPPVec;
    placeholderPPVec.reserve(placeholderMap.size());
    for (const auto& [placeholder, jsonPath] : placeholderMap)
    {
        placeholderPPVec.emplace_back(placeholder, json::PointerPath(jsonPath));
    }

    auto name = fmt::format("write.output({}/{})", syntax::asset::INDEXER_OUTPUT_KEY, indexName);
    const auto skippedTrace = fmt::format("{} -> Success (skipped in test mode)", name);
    // The name may hold `${field}` placeholders, so it never becomes a format string: these traces are concatenated
    const auto missingFieldTrace = name + " -> Couldn't get field ";
    const auto tooLongTrace = name + " -> Index name '";

    // In test mode nothing is indexed (I183), so the stage builds without a connector (event processing off, I189)
    const auto isTestMode = buildCtx->isTestMode();
    auto wic = iConnector.lock();
    if (!wic && !isTestMode)
    {
        throw std::runtime_error("Indexer connector is not available");
    }

    return base::Term<base::EngineOp>::create(
        name,
        [indexName, placeholderPPVec, wic = std::move(wic), skippedTrace, missingFieldTrace, tooLongTrace, isTestMode](
            base::Event event) -> base::result::Result<base::Event>
        {
            std::string finalIndexName = indexName;
            for (const auto& [placeholder, jsonPathPP] : placeholderPPVec)
            {
                std::string fieldValue;
                if (event->getString(fieldValue, jsonPathPP) != json::RetGet::Success)
                {
                    RETURN_FAILURE(isTestMode, event, missingFieldTrace + placeholder + " from event");
                }

                // Replace all occurrences of the placeholder in the indexName
                size_t pos = 0;
                while ((pos = finalIndexName.find(placeholder, pos)) != std::string::npos)
                {
                    finalIndexName.replace(pos, placeholder.length(), fieldValue);
                    pos += fieldValue.length();
                }
            }

            if (finalIndexName.size() > 255)
            {
                RETURN_FAILURE(isTestMode, event, tooLongTrace + finalIndexName + "' exceeds 255 characters limit");
            }

            // The checks above still run in test mode; only the write is skipped
            if (isTestMode)
            {
                return base::result::makeSuccess<decltype(event)>(event, skippedTrace);
            }

            wic->index(std::move(finalIndexName), event->str());

            return base::result::makeSuccess<decltype(event)>(event);
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
