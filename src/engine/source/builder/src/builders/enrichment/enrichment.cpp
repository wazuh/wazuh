#include "enrichment.hpp"

#include <exception>
#include <fmt/format.h>

#include <cmstore/categories.hpp>
#include <fastmetrics/registry.hpp>

namespace
{
constexpr std::string_view JPATH_ORIGIN_SPACE = "/wazuh/space/name";                   ///< wazuh.space.name
const json::PointerPath PP_INTEGRATION_CATEGORY {"/wazuh/integration/category"};       ///< wazuh.integration.category
const std::string ENRICHMENT_SPACE_TRACEABLE_NAME = "enrichment/OriginSpace";
const std::string UNCLASSIFIED_FILTER_TRACEABLE_NAME = "filter/UnclassifiedEvents";
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

std::pair<base::Expression, std::string> getSpaceEnrichment(const cm::store::dataType::Policy& policy, bool trace)
{
    // Setting origin space

    auto op = base::Term<base::EngineOp>::create(
        ENRICHMENT_SPACE_TRACEABLE_NAME,
        [originSpace = policy.getOriginSpace(), trace](base::Event event) -> base::result::Result<base::Event>
        {
            event->setString(originSpace, JPATH_ORIGIN_SPACE);
            if (trace)
            {
                return base::result::makeSuccess<decltype(event)>(event, "[map: $wazuh.space.name] -> Success");
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, trace), ENRICHMENT_SPACE_TRACEABLE_NAME);
}

std::pair<base::Expression, std::string> getUnclassifiedFilter(const cm::store::dataType::Policy& policy, bool trace)
{
    // Filter unclassified events based on policy configuration
    const bool shouldIndex = policy.shouldIndexUnclassifiedEvents();

    auto op = base::Term<base::EngineOp>::create(
        UNCLASSIFIED_FILTER_TRACEABLE_NAME,
        [shouldIndex, trace](base::Event event) -> base::result::Result<base::Event>
        {
            if (shouldIndex && !trace)
            {
                // If indexing unclassified events is enabled and tracing is disabled, allow the event without
                // modification
                return base::result::makeSuccess<decltype(event)>(event);
            }

            // Get the integration category
            const auto isUnclassified = [&]() -> bool
            {
                std::string_view categoryStr;
                return event->getString(categoryStr, PP_INTEGRATION_CATEGORY) == json::RetGet::Success
                       && categoryStr == cm::store::categories::UNCLASSIFIED_CATEGORY;
            }();

            // If category is unclassified and indexing is disabled, drop the event
            if (isUnclassified && !shouldIndex)
            {
                if (trace)
                {
                    return base::result::makeFailure<decltype(event)>(
                        event,
                        "dropUnclassifiedEvent() -> Event dropped because it is unclassified and policy "
                        "index_unclassified_events=false");
                }
                return base::result::makeFailure<decltype(event)>(event);
            }

            // Otherwise, allow the event to continue
            return base::result::makeSuccess<decltype(event)>(
                event,
                isUnclassified ? "dropUnclassifiedEvent() -> Event is unclassified but policy "
                                 "index_unclassified_events=true, allowing event"
                               : "dropUnclassifiedEvent() -> Event is classified, allowing event");
        });

    return std::make_pair(makeTraceableSuccessExpression(op, trace), UNCLASSIFIED_FILTER_TRACEABLE_NAME);
}

std::pair<base::Expression, std::string>
getDiscardedEventsFilter(const cm::store::dataType::Policy& policy,
                         bool trace,
                         const std::shared_ptr<fastmetrics::ICounter>& discardedCounter)
{
    const bool shouldIndex = policy.shouldIndexDiscardedEvents();
    const auto discardFieldPath = json::Json::formatJsonPath(syntax::asset::discard::TARGET_FIELD);

    // Per-space metric: count events marked as discarded in this space
    std::shared_ptr<fastmetrics::ICounter> spaceDiscardedCounter = discardedCounter;
    if (!spaceDiscardedCounter)
    {
        const auto spaceName = policy.getOriginSpace();
        spaceDiscardedCounter = fastmetrics::manager().getOrCreateCounter("space." + spaceName + ".events.discarded");
    }

    auto op = base::Term<base::EngineOp>::create(
        DISCARDED_EVENTS_FILTER_TRACEABLE_NAME,
        [shouldIndex, discardFieldPath, trace, spaceDiscardedCounter](
            base::Event event) -> base::result::Result<base::Event>
        {
            // Policy enables indexing of discarded events
            if (shouldIndex)
            {
                if (trace)
                {
                    return base::result::makeSuccess<decltype(event)>(event, POSITIVE_INDEXED_BY_DISCARDED_TRUE);
                }
                return base::result::makeSuccess<decltype(event)>(event);
            }

            // Check if the discard field exists and is true
            auto discardValue = event->getBool(discardFieldPath);
            if (discardValue && discardValue.value())
            {
                spaceDiscardedCounter->add(1);
                if (trace)
                {
                    return base::result::makeFailure<decltype(event)>(event,
                                                                      NEGATIVE_INDEXED_BY_DISCARDED_TRUE_FIELD_FALSE);
                }
                return base::result::makeFailure<decltype(event)>(event);
            }

            if (trace)
            {
                return base::result::makeSuccess<decltype(event)>(event, POSITIVE_INDEXED_BY_DISCARDED_FALSE);
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, trace), DISCARDED_EVENTS_FILTER_TRACEABLE_NAME);
}

std::pair<base::Expression, std::string> getCleanupDecoderVariables(bool enabled, bool trace)
{
    auto op = base::Term<base::EngineOp>::create(
        CLEANUP_DECODER_VARIABLES_TRACEABLE_NAME,
        [enabled, trace](base::Event event) -> base::result::Result<base::Event>
        {
            if (!enabled)
            {
                if (trace)
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
                if (trace)
                {
                    return base::result::makeFailure<decltype(event)>(
                        event,
                        fmt::format("cleanupDecoderTemporaryVariables() -> Failure: Could not remove root keys "
                                    "prefixed with '_' ({})",
                                    e.what()));
                }
                return base::result::makeFailure<decltype(event)>(event);
            }

            if (trace)
            {
                return base::result::makeSuccess<decltype(event)>(
                    event, "cleanupDecoderTemporaryVariables() -> Success: Removed root keys prefixed with '_'");
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, trace), CLEANUP_DECODER_VARIABLES_TRACEABLE_NAME);
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
