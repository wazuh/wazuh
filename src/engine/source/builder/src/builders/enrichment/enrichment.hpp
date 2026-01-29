#ifndef _BUILDER_ENRICHMENT_ENRICHMENT_HPP
#define _BUILDER_ENRICHMENT_ENRICHMENT_HPP

#include <cmstore/datapolicy.hpp>

#include "builders/types.hpp"

namespace builder::builders::enrichment
{

/**
 * @brief Get the enrichment expression for the policy.
 *
 * @param policy Policy data.
 * @param trace Enable tracing in the enrichment expression.
 * @return base::Expression Enrichment expression.
 */
base::Expression getEnrichmentExpression(const cm::store::dataType::Policy& policy, bool trace);

} // namespace builder::builders::enrichment

#endif // _BUILDER_ENRICHMENT_ENRICHMENT_HPP
