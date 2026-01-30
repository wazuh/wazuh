#ifndef _BUILDER_ENRICHMENT_ENRICHMENT_HPP
#define _BUILDER_ENRICHMENT_ENRICHMENT_HPP

#include <utility>

#include <cmstore/datapolicy.hpp>

#include "builders/types.hpp"

namespace builder::builders::enrichment
{

/**
 * @brief Get the enrichment expression and traceable name for the space defined in the policy.
 *
 * @param policy Policy data.
 * @param trace Enable tracing in the enrichment expression.
 * @return std::pair<base::Expression, std::string> The built enrichment expression and its traceable name.
 */
std::pair<base::Expression, std::string> getSpaceEnrichment(const cm::store::dataType::Policy& policy, bool trace);

} // namespace builder::builders::enrichment

#endif // _BUILDER_ENRICHMENT_ENRICHMENT_HPP
