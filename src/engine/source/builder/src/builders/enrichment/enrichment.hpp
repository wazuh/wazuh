#ifndef _BUILDER_ENRICHMENT_ENRICHMENT_HPP
#define _BUILDER_ENRICHMENT_ENRICHMENT_HPP

#include <cmstore/datapolicy.hpp>

#include "builders/types.hpp"

namespace builder::builders::enrichment
{

base::Expression getEnrichmentExpression(const cm::store::dataType::Policy& policy);

} // namespace builder::builders::enrichment

#endif // _BUILDER_ENRICHMENT_ENRICHMENT_HPP
