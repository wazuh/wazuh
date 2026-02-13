#include "enrichment.hpp"

#include <cmstore/categories.hpp>

namespace
{
constexpr std::string_view JPATH_ORIGIN_SPACE = "/wazuh/space/name";                   ///< wazuh.space.name
constexpr std::string_view JPATH_INTEGRATION_CATEGORY = "/wazuh/integration/category"; ///< wazuh.integration.category
const std::string ENRICHMENT_SPACE_TRACEABLE_NAME = "enrichment/OriginSpace";
const std::string UNCLASSIFIED_FILTER_TRACEABLE_NAME = "filter/UnclassifiedEvents";

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
            // Get the integration category
            auto categoryOpt = event->getString(JPATH_INTEGRATION_CATEGORY);

            // If category is unclassified and indexing is disabled, drop the event
            if (categoryOpt.has_value() && categoryOpt.value() == cm::store::categories::UNCLASSIFIED_CATEGORY
                && !shouldIndex)
            {
                if (trace)
                {
                    return base::result::makeFailure<decltype(event)>(
                        event, "Event with unclassified category dropped (index_unclassified_events=false)");
                }
                return base::result::makeFailure<decltype(event)>(event);
            }

            // Otherwise, allow the event to continue
            if (trace)
            {
                return base::result::makeSuccess<decltype(event)>(
                    event,
                    categoryOpt.has_value() && categoryOpt.value() == cm::store::categories::UNCLASSIFIED_CATEGORY
                        ? "Unclassified event allowed (index_unclassified_events=true)"
                        : "Event is not unclassified, continuing normally");
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, trace), UNCLASSIFIED_FILTER_TRACEABLE_NAME);
}

} // namespace builder::builders::enrichment
