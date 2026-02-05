#ifndef _BUILDER_ENRICHMENT_ENRICHMENT_HPP
#define _BUILDER_ENRICHMENT_ENRICHMENT_HPP

#include <utility>

#include <cmstore/datapolicy.hpp>
#include <geo/imanager.hpp>

#include "builders/types.hpp"

namespace builder::builders::enrichment
{

/**
 * @brief Make a traceable success expression.
 *
 * @param expr The expression to make traceable.
 * @param trace Enable tracing.
 * @return base::Expression The traceable expression, or the original expression if tracing is disabled.
 */
inline base::Expression makeTraceableSuccessExpression(const base::Expression& expr, bool trace)
{
    if (!trace)
    {
        return expr;
    }
    static const auto successTraceable =
        base::Term<base::EngineOp>::create("AcceptAll", [](auto e) { return base::result::makeSuccess(e, "SUCCESS"); });
    return base::Implication::create("TraceableSuccess", expr, successTraceable);
}

/**
 * @brief Get the enrichment expression and traceable name for the space defined in the policy.
 *
 * @param policy Policy data.
 * @param trace Enable tracing in the enrichment expression.
 * @return std::pair<base::Expression, std::string> The built enrichment expression and its traceable name.
 */
std::pair<base::Expression, std::string> getSpaceEnrichment(const cm::store::dataType::Policy& policy, bool trace);

/**
 * @brief Get the Geo Enrichment Builder
 *
 * @param geoManager Geo manager instance, used to create 1 locator per enrichment.
 * @return EnrichmentBuilder
 */
EnrichmentBuilder getGeoEnrichmentBuilder(const std::shared_ptr<geo::IManager>& geoManager);

} // namespace builder::builders::enrichment

#endif // _BUILDER_ENRICHMENT_ENRICHMENT_HPP
