#include "enrichment.hpp"

#include <cmstore/categories.hpp>

namespace
{
constexpr std::string_view JPATH_ORIGIN_SPACE = "/wazuh/space/name";                   ///< wazuh.space.name
constexpr std::string_view JPATH_INTEGRATION_CATEGORY = "/wazuh/integration/category"; ///< wazuh.integration.category
const std::string ENRICHMENT_SPACE_TRACEABLE_NAME = "enrichment/OriginSpace";
const std::string UNCLASSIFIED_FILTER_TRACEABLE_NAME = "filter/UnclassifiedEvents";
const std::string DISCARDED_EVENTS_FILTER_TRACEABLE_NAME = "filter/DiscardedEvents";

constexpr auto POSITIVE_INDEXED_BY_DISCARDED_TRUE = "Discard_event() -> Success: Event will be indexed (index_discarded_events=true)";
constexpr auto NEGATIVE_INDEXED_BY_DISCARDED_TRUE_FIELD_FALSE =
    "Discard_event() -> Failure: Event won't be indexed (wazuh.space.event_discarded=true and index_discarded_events=false)";
constexpr auto POSITIVE_INDEXED_BY_DISCARDED_FALSE = "Discard_event() -> Success: Event will be indexed (wazuh.space.event_discarded=false)";

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
                auto categoryOpt = event->getString(JPATH_INTEGRATION_CATEGORY);
                return categoryOpt.has_value() && categoryOpt.value() == cm::store::categories::UNCLASSIFIED_CATEGORY;
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

std::pair<base::Expression, std::string> getDiscardedEventsFilter(const cm::store::dataType::Policy& policy, bool trace)
{
    const bool shouldIndex = policy.shouldIndexDiscardedEvents();
    const auto discardFieldPath = json::Json::formatJsonPath(syntax::asset::discard::TARGET_FIELD);

    auto op = base::Term<base::EngineOp>::create(
        DISCARDED_EVENTS_FILTER_TRACEABLE_NAME,
        [shouldIndex, discardFieldPath, trace](base::Event event) -> base::result::Result<base::Event>
        {
            // Policy enables indexing of discarded events
            if (shouldIndex)
            {
                if (trace)
                {
                    return base::result::makeSuccess<decltype(event)>(
                        event, POSITIVE_INDEXED_BY_DISCARDED_TRUE);
                }
                return base::result::makeSuccess<decltype(event)>(event);
            }

            // Check if the discard field exists and is true
            auto discardValue = event->getBool(discardFieldPath);
            if (discardValue && discardValue.value())
            {
                if (trace)
                {
                    return base::result::makeFailure<decltype(event)>(
                        event, NEGATIVE_INDEXED_BY_DISCARDED_TRUE_FIELD_FALSE);
                }
                return base::result::makeFailure<decltype(event)>(event);
            }

            if (trace)
            {
                return base::result::makeSuccess<decltype(event)>(
                    event, POSITIVE_INDEXED_BY_DISCARDED_FALSE);
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, trace), DISCARDED_EVENTS_FILTER_TRACEABLE_NAME);
}

} // namespace builder::builders::enrichment
