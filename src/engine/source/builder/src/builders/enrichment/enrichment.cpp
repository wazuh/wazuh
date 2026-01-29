#include "enrichment.hpp"

namespace
{
constexpr std::string_view JPATH_ORIGIN_SPACE = "/wazuh/space/name"; ///< wazuh.space.name
}

namespace builder::builders::enrichment
{

base::Expression getEnrichmentExpression(const cm::store::dataType::Policy& policy, bool trace)
{
    // Setting origin space
    return base::Term<base::EngineOp>::create(
        "enrichment.setOriginSpace",
        [originSpace = policy.getOriginSpace(), trace](base::Event event) -> base::result::Result<base::Event>
        {
            event->setString(originSpace, JPATH_ORIGIN_SPACE);
            if (trace)
            {
                return base::result::makeSuccess<decltype(event)>(event, "[enrichment] Set origin space");
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });
}

} // namespace builder::builders::enrichment
