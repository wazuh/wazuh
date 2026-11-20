// SPDX-License-Identifier: AGPL-3.0-or-later
#include "indexerOutput.hpp"

#include <algorithm>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string_view>
#include <unordered_map>

#include <base/logging.hpp>

#include "builders/utils.hpp"

namespace builder::builders
{

namespace
{
constexpr std::string_view INDEX_PREFIX = "wazuh-events-v5-";
constexpr size_t MAX_INDEX_NAME_SIZE = 255;

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

/**
 * @brief Whether an event field value may take the place of a placeholder in an index name.
 *
 * The value becomes part of a name the connector writes into a bulk action line and a URL, so it is held to the
 * characters the name itself may use, plus '_'. Anything else (a quote, a slash, a space, an upper-case letter) is
 * refused, never escaped.
 */
bool isIndexNameValue(std::string_view value)
{
    return std::all_of(
        value.begin(),
        value.end(),
        [](const char c)
        { return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_'; });
}
} // namespace

std::shared_ptr<NotIndexedLogThrottle> notIndexedLogThrottleFor(const std::string& operationName)
{
    static std::mutex mutex;
    static std::unordered_map<std::string, std::weak_ptr<NotIndexedLogThrottle>> throttles;

    std::lock_guard lock {mutex};
    if (auto it = throttles.find(operationName); it != throttles.end())
    {
        if (auto throttle = it->second.lock(); throttle)
        {
            return throttle;
        }
    }

    // Names of outputs no longer built would otherwise stay here forever
    for (auto it = throttles.begin(); it != throttles.end();)
    {
        it = it->second.expired() ? throttles.erase(it) : std::next(it);
    }

    auto throttle = std::make_shared<NotIndexedLogThrottle>();
    throttles[operationName] = throttle;
    return throttle;
}

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
    const auto successTrace = fmt::format("{} -> Success", name);

    // Get shared ptr
    auto wic = iConnector.lock();
    if (!wic)
    {
        throw std::runtime_error("Indexer connector is not available");
    }

    // The index name and the field values are user content: they are never used as a format string. An event that
    // cannot be indexed is a failure of the operation with the cause in the trace; outside test mode it is also
    // reported by a rate-limited warning (without the event).
    auto notIndexedLog = notIndexedLogThrottleFor(name);

    return base::Term<base::EngineOp>::create(
        name,
        [name, indexName, placeholderPPVec, wic, successTrace, notIndexedLog, isTestMode = buildCtx->isTestMode()](
            base::Event event) -> base::result::Result<base::Event>
        {
            // An event that cannot be indexed. `trace` builds the cause for the trace of a test session and `log` the
            // one for the manager log, which must not carry event content (the expanded index name is built from
            // field values, of any size). Each is called only when its text is used.
            auto fail = [&](auto&& trace, auto&& log) -> base::result::Result<base::Event>
            {
                if (isTestMode)
                {
                    return base::result::makeFailure(event, name + " -> " + trace());
                }

                if (const auto suppressed = notIndexedLog->record(); suppressed)
                {
                    if (*suppressed == 0)
                    {
                        LOG_WARNING("[builder] Event not indexed by '{}': {}", name, log());
                    }
                    else
                    {
                        LOG_WARNING("[builder] Event not indexed by '{}': {} ({} more events not indexed by this "
                                    "output since the previous report)",
                                    name,
                                    log(),
                                    *suppressed);
                    }
                }
                return base::result::makeFailure(event);
            };

            std::string finalIndexName = indexName;
            for (const auto& [placeholder, jsonPathPP] : placeholderPPVec)
            {
                std::string fieldValue;
                if (event->getString(fieldValue, jsonPathPP) != json::RetGet::Success)
                {
                    // The placeholder comes from the asset, not from the event
                    const auto cause = [&placeholder = placeholder]()
                    {
                        return "Couldn't get field " + placeholder + " from event";
                    };
                    return fail(cause, cause);
                }

                if (!isIndexNameValue(fieldValue))
                {
                    // Neither cause carries the value: it is event content, of any size
                    const auto cause = [&placeholder = placeholder]()
                    {
                        return "Field " + placeholder + " holds characters not allowed in an index name";
                    };
                    return fail(cause, cause);
                }

                // Replace all occurrences of the placeholder in the indexName
                size_t pos = 0;
                while ((pos = finalIndexName.find(placeholder, pos)) != std::string::npos)
                {
                    finalIndexName.replace(pos, placeholder.length(), fieldValue);
                    pos += fieldValue.length();
                }
            }

            if (finalIndexName.size() > MAX_INDEX_NAME_SIZE)
            {
                return fail([&]() { return "Index name '" + finalIndexName + "' exceeds 255 characters limit"; },
                            [&]()
                            {
                                return "Index name exceeds 255 characters limit ("
                                       + std::to_string(finalIndexName.size()) + " characters)";
                            });
            }

            wic->index(finalIndexName, event->str());

            // The failures suppressed after the last warning, reported once its window is over
            if (!isTestMode)
            {
                if (const auto suppressed = notIndexedLog->pending(); suppressed)
                {
                    LOG_WARNING(
                        "[builder] {} more events not indexed by '{}' since the previous report", *suppressed, name);
                }
            }

            RETURN_SUCCESS(isTestMode, event, successTrace);
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
