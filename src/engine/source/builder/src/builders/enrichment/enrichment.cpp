// SPDX-License-Identifier: AGPL-3.0-or-later
#include "enrichment.hpp"

#include <exception>
#include <unordered_map>

#include <fmt/format.h>
#include <fmt/ranges.h>

#include <base/eventParser.hpp>
#include <base/logging.hpp>
#include <cmstore/categories.hpp>
#include <fastmetrics/registry.hpp>

#include "syntax.hpp"

namespace
{
constexpr std::string_view JPATH_ORIGIN_SPACE = "/wazuh/space/name"; ///< wazuh.space.name
const std::string ENRICHMENT_SPACE_TRACEABLE_NAME = "enrichment/OriginSpace";
const std::string DISCARDED_EVENTS_FILTER_TRACEABLE_NAME = "filter/DiscardedEvents";
const std::string CLEANUP_DECODER_VARIABLES_TRACEABLE_NAME = "cleanup/DecoderTemporaryVariables";

constexpr auto POSITIVE_INDEXED_BY_DISCARDED_TRUE =
    "Discard_event() -> Success: Event will be indexed (index_discarded_events=true)";
constexpr auto NEGATIVE_INDEXED_BY_DISCARDED_TRUE_FIELD_FALSE =
    "Discard_event() -> Failure: Event won't be indexed (wazuh.space.event_discarded=true and "
    "index_discarded_events=false)";
constexpr auto POSITIVE_INDEXED_BY_DISCARDED_FALSE =
    "Discard_event() -> Success: Event will be indexed (wazuh.space.event_discarded=false)";

} // namespace
namespace builder::builders::enrichment
{

std::pair<base::Expression, std::string> getSpaceEnrichment(const cm::store::dataType::Policy& policy, bool isTestMode)
{
    // Setting origin space

    auto op = base::Term<base::EngineOp>::create(
        ENRICHMENT_SPACE_TRACEABLE_NAME,
        [originSpace = policy.getOriginSpace(), isTestMode](base::Event event) -> base::result::Result<base::Event>
        {
            event->setString(originSpace, JPATH_ORIGIN_SPACE);
            if (isTestMode)
            {
                return base::result::makeSuccess<decltype(event)>(event, "[map: $wazuh.space.name] -> Success");
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, isTestMode), ENRICHMENT_SPACE_TRACEABLE_NAME);
}

std::pair<base::Expression, std::string>
getDiscardedEventsFilter(const cm::store::dataType::Policy& policy,
                         bool isTestMode,
                         const std::shared_ptr<fastmetrics::ICounter>& discardedCounter)
{
    const bool shouldIndex = policy.shouldIndexDiscardedEvents();
    const auto discardFieldPath = json::Json::formatJsonPath(syntax::asset::discard::TARGET_FIELD);

    auto op = base::Term<base::EngineOp>::create(
        DISCARDED_EVENTS_FILTER_TRACEABLE_NAME,
        [shouldIndex, discardFieldPath, isTestMode, discardedCounter](
            base::Event event) -> base::result::Result<base::Event>
        {
            // Policy enables indexing of discarded events
            if (shouldIndex)
            {
                if (isTestMode)
                {
                    return base::result::makeSuccess<decltype(event)>(event, POSITIVE_INDEXED_BY_DISCARDED_TRUE);
                }
                return base::result::makeSuccess<decltype(event)>(event);
            }

            // Check if the discard field exists and is true
            auto discardValue = event->getBool(discardFieldPath);
            if (discardValue && discardValue.value())
            {
                discardedCounter->add(1);
                if (isTestMode)
                {
                    return base::result::makeFailure<decltype(event)>(event,
                                                                      NEGATIVE_INDEXED_BY_DISCARDED_TRUE_FIELD_FALSE);
                }
                return base::result::makeFailure<decltype(event)>(event);
            }

            if (isTestMode)
            {
                return base::result::makeSuccess<decltype(event)>(event, POSITIVE_INDEXED_BY_DISCARDED_FALSE);
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, isTestMode), DISCARDED_EVENTS_FILTER_TRACEABLE_NAME);
}

UnclassifiedDropReporter::UnclassifiedDropReporter(std::string spaceName, std::chrono::seconds interval)
    : m_spaceName(std::move(spaceName))
    , m_interval(interval)
{
}

std::shared_ptr<UnclassifiedDropReporter> UnclassifiedDropReporter::forSpace(const std::string& spaceName)
{
    static std::mutex registryMutex;
    static std::unordered_map<std::string, std::weak_ptr<UnclassifiedDropReporter>> registry;

    std::lock_guard lock(registryMutex);
    for (auto it = registry.begin(); it != registry.end();)
    {
        it = it->second.expired() ? registry.erase(it) : std::next(it);
    }

    auto& slot = registry[spaceName];
    auto reporter = slot.lock();
    if (!reporter)
    {
        reporter = std::make_shared<UnclassifiedDropReporter>(spaceName);
        slot = reporter;
    }
    return reporter;
}

std::string_view UnclassifiedDropReporter::truncateSource(std::string_view source)
{
    if (source.size() <= MAX_SOURCE_LENGTH)
    {
        return source;
    }

    // Back off over UTF-8 continuation bytes (10xxxxxx) so the cut lands on a character boundary.
    auto cut = MAX_SOURCE_LENGTH;
    while (cut > 0 && (static_cast<unsigned char>(source[cut]) & 0xC0) == 0x80)
    {
        --cut;
    }
    return source.substr(0, cut);
}

std::string UnclassifiedDropReporter::sanitizeSource(std::string_view source)
{
    std::string sanitized;
    sanitized.reserve(source.size());
    for (const char ch : source)
    {
        const auto byte = static_cast<unsigned char>(ch);
        if (byte < 0x20 || byte == 0x7F)
        {
            sanitized.append(fmt::format("\\x{:02X}", byte));
        }
        else
        {
            sanitized.push_back(ch);
        }
    }
    return sanitized;
}

void UnclassifiedDropReporter::sampleSource(std::string_view source, SourceCache* cache)
{
    // Already added by this caller in the current period: skip the shared lock.
    if (cache && cache->period == m_period.load(std::memory_order_relaxed) && cache->sources.count(source) != 0)
    {
        return;
    }

    // A contended lock only skips this event's source, never the count; the cache is not marked, so it retries.
    std::unique_lock lock(m_sourcesMutex, std::try_to_lock);
    if (!lock.owns_lock())
    {
        return;
    }

    if (m_sources.size() < MAX_SOURCES)
    {
        auto sanitized = sanitizeSource(source);
        if (m_sources.find(sanitized) == m_sources.end())
        {
            m_sources.emplace(std::move(sanitized));
            m_sourcesFull.store(m_sources.size() >= MAX_SOURCES, std::memory_order_relaxed);
        }
    }

    if (cache)
    {
        const auto period = m_period.load(std::memory_order_relaxed);
        if (cache->period != period)
        {
            cache->sources.clear();
            cache->period = period;
        }
        if (cache->sources.size() < MAX_SOURCES)
        {
            cache->sources.emplace(source);
        }
    }
}

std::optional<std::string>
UnclassifiedDropReporter::record(std::string_view location, Clock::time_point now, SourceCache* cache)
{
    m_dropped.fetch_add(1, std::memory_order_relaxed);

    if (!location.empty() && !m_sourcesFull.load(std::memory_order_relaxed))
    {
        sampleSource(truncateSource(location), cache);
    }

    auto nextReport = m_nextReport.load(std::memory_order_relaxed);
    const auto nowRep = now.time_since_epoch().count();
    if (nowRep < nextReport
        || !m_nextReport.compare_exchange_strong(nextReport, (now + m_interval).time_since_epoch().count()))
    {
        return std::nullopt;
    }

    // Not atomic with the swap below: a source sampled between the two is listed in this warning while its event is
    // counted in the next one. Only the warning text is affected; the counts always add up.
    const auto dropped = m_dropped.exchange(0, std::memory_order_relaxed);
    std::set<std::string, std::less<>> sources;
    {
        std::lock_guard lock(m_sourcesMutex);
        sources.swap(m_sources);
        m_sourcesFull.store(false, std::memory_order_relaxed);
        m_period.fetch_add(1, std::memory_order_relaxed);
    }

    // Raw indexing runs before the policy and is not known here, so the message does not claim raw copies are lost.
    return fmt::format(
        "Space '{}': {} unclassified event(s) not indexed as processed events since the last report "
        "(index_unclassified_events=false); a raw copy is kept only if index_raw_events is enabled. No enabled "
        "integration decoded them; sources: [{}]. Enable the integration for these sources if one is available, or "
        "enable index_unclassified_events to index them as unclassified events. Next report in {}s at the earliest.",
        m_spaceName,
        dropped,
        sources.empty() ? std::string {"unknown"} : fmt::format("{}", fmt::join(sources, ", ")),
        std::chrono::duration_cast<std::chrono::seconds>(m_interval).count());
}

std::shared_ptr<UnclassifiedDropReporter> getUnclassifiedDropReporter(const cm::store::dataType::Policy& policy,
                                                                      bool isTestMode)
{
    if (isTestMode || policy.shouldIndexUnclassifiedEvents())
    {
        return nullptr;
    }
    return UnclassifiedDropReporter::forSpace(policy.getOriginSpace());
}

base::Expression postOutputUnclassifiedCounter(const std::string& spaceName,
                                               std::shared_ptr<fastmetrics::ICounter> unclassifiedCounter,
                                               std::shared_ptr<UnclassifiedDropReporter> dropReporter)
{
    return base::Term<base::EngineOp>::create(
        "postOutputUnclassified",
        // Each router worker builds its own policy, so the cache is only touched by that worker's thread
        [unclassifiedCounter,
         dropReporter,
         cache = UnclassifiedDropReporter::SourceCache {},
         ppIntegrationCategory = json::PointerPath {syntax::asset::CATEGORY_PATH},
         ppLocation = json::PointerPath {base::eventParsers::EVENT_LOCATION_ID}](
            base::Event event) mutable -> base::result::Result<base::Event>
        {
            std::string_view category;
            if (event->getString(category, ppIntegrationCategory) == json::RetGet::Success
                && category == cm::store::categories::UNCLASSIFIED_CATEGORY)
            {
                unclassifiedCounter->add(1);

                if (dropReporter)
                {
                    std::string_view location;
                    event->getString(location, ppLocation);
                    if (auto warning = dropReporter->record(location, UnclassifiedDropReporter::Clock::now(), &cache))
                    {
                        LOG_WARNING("{}", *warning);
                    }
                }
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });
}

std::pair<base::Expression, std::string> getCleanupDecoderVariables(bool enabled, bool isTestMode)
{
    auto op = base::Term<base::EngineOp>::create(
        CLEANUP_DECODER_VARIABLES_TRACEABLE_NAME,
        [enabled, isTestMode](base::Event event) -> base::result::Result<base::Event>
        {
            if (!enabled)
            {
                if (isTestMode)
                {
                    return base::result::makeSuccess<decltype(event)>(
                        event, "cleanupDecoderTemporaryVariables() -> Skipped: Cleanup disabled by policy");
                }
                return base::result::makeSuccess<decltype(event)>(event);
            }

            try
            {
                event->eraseRootKeysByPrefix("_");
            }
            catch (const std::exception& e)
            {
                if (isTestMode)
                {
                    return base::result::makeFailure<decltype(event)>(
                        event,
                        fmt::format("cleanupDecoderTemporaryVariables() -> Failure: Could not remove root keys "
                                    "prefixed with '_' ({})",
                                    e.what()));
                }
                return base::result::makeFailure<decltype(event)>(event);
            }

            if (isTestMode)
            {
                return base::result::makeSuccess<decltype(event)>(
                    event, "cleanupDecoderTemporaryVariables() -> Success: Removed root keys prefixed with '_'");
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, isTestMode), CLEANUP_DECODER_VARIABLES_TRACEABLE_NAME);
}

base::Expression makeFilterDiscardCounter(const base::Expression& phaseExpr,
                                          const std::shared_ptr<fastmetrics::ICounter>& counter,
                                          const std::string& name)
{
    // Create a term that increments the counter and returns failure
    auto counterTerm =
        base::Term<base::EngineOp>::create(name,
                                           [counter](base::Event event) -> base::result::Result<base::Event>
                                           {
                                               counter->add(1);
                                               return base::result::makeFailure<decltype(event)>(event);
                                           });

    // Wrap: if phaseExpr fails, run counterTerm (which increments and propagates failure)
    // phaseExpr => success path (pass through), failure path => counterTerm
    // We use Or: try phaseExpr first, if it fails try counterTerm
    return base::Or::create(name + "/wrapper", {phaseExpr, counterTerm});
}

} // namespace builder::builders::enrichment
