#include "enrichment.hpp"

namespace
{
constexpr std::string_view JPATH_ORIGIN_SPACE = "/wazuh/space/name"; ///< wazuh.space.name
}

namespace builder::builders::enrichment
{

base::Expression getEnrichmentExpression(const cm::store::dataType::Policy& policy)
{
    // Setting origin space
    return base::Term<base::EngineOp>::create(
        "enrichment.setOriginSpace",
        [originSpace = policy.getOriginSpace()](base::Event event) -> base::result::Result<base::Event>
        {
            event->setString(originSpace, JPATH_ORIGIN_SPACE);
            return base::result::Result<base::Event>(event, "Set space name", true);
        });
}

} // namespace builder::builders::enrichment
