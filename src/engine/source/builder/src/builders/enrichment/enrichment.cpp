#include "enrichment.hpp"

namespace
{
constexpr std::string_view JPATH_ORIGIN_SPACE = "/wazuh/space/name"; ///< wazuh.space.name
const std::string ENRICHMENT_SPACE_TRACEABLE_NAME = "enrichment/OriginSpace";

const auto successTraceable =
    base::Term<base::EngineOp>::create("AcceptAll", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });

base::Expression makeTraceableSuccessExpression(const base::Expression& expr, bool trace)
{
    if (!trace)
    {
        return expr;
    }
    return base::Implication::create("TraceableSuccess", expr, successTraceable);
}

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

} // namespace builder::builders::enrichment
