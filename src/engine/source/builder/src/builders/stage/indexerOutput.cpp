// SPDX-License-Identifier: AGPL-3.0-or-later
#include "indexerOutput.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string_view>

#include <base/logging.hpp>

#include "builders/utils.hpp"

namespace builder::builders
{

namespace
{
constexpr std::string_view INDEX_PREFIX = "wazuh-events-v5-";
constexpr size_t MAX_INDEX_NAME_SIZE = 255;
constexpr auto NOT_INDEXED_LOG_WINDOW = std::chrono::seconds(60);

/**
 * @brief Rate limit of the "event not indexed" warning of one output operation.
 *
 * The first occurrence is logged, then at most one per window, carrying how many were suppressed since the previous
 * line. Shared by every worker thread running the same operation.
 */
class NotIndexedLogThrottle
{
public:
    using Clock = std::chrono::steady_clock;

    /**
     * @brief Record one occurrence.
     *
     * @return The number of occurrences suppressed since the previous logged one when this one must be logged,
     * std::nullopt when it must be suppressed.
     */
    std::optional<std::uint64_t> record()
    {
        const auto now = Clock::now();
        std::lock_guard lock {m_mutex};
        if (m_hasLogged && now - m_lastLog < NOT_INDEXED_LOG_WINDOW)
        {
            ++m_suppressed;
            return std::nullopt;
        }

        const auto suppressed = m_suppressed;
        m_suppressed = 0;
        m_lastLog = now;
        m_hasLogged = true;
        return suppressed;
    }

private:
    std::mutex m_mutex;
    Clock::time_point m_lastLog {};
    bool m_hasLogged {false};
    std::uint64_t m_suppressed {0};
};

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
    auto notIndexedLog = std::make_shared<NotIndexedLogThrottle>();

    return base::Term<base::EngineOp>::create(
        name,
        [name, indexName, placeholderPPVec, wic, successTrace, notIndexedLog, isTestMode = buildCtx->isTestMode()](
            base::Event event) -> base::result::Result<base::Event>
        {
            auto fail = [&](const std::string& cause) -> base::result::Result<base::Event>
            {
                if (isTestMode)
                {
                    return base::result::makeFailure(event, name + " -> " + cause);
                }

                if (const auto suppressed = notIndexedLog->record(); suppressed)
                {
                    if (*suppressed == 0)
                    {
                        LOG_WARNING("[builder] Event not indexed by '{}': {}", name, cause);
                    }
                    else
                    {
                        LOG_WARNING("[builder] Event not indexed by '{}': {} ({} more events not indexed by this "
                                    "output since the previous report)",
                                    name,
                                    cause,
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
                    return fail("Couldn't get field " + placeholder + " from event");
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
                return fail("Index name '" + finalIndexName + "' exceeds 255 characters limit");
            }

            wic->index(finalIndexName, event->str());

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
