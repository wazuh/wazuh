#ifndef _BUILDER_BUILDERS_STAGE_PARSE_HPP
#define _BUILDER_BUILDERS_STAGE_PARSE_HPP

#include <logpar/logpar.hpp>

#include "builders/types.hpp"

namespace builder::builders
{

/**
 * @brief Builds parsing stage to be able to get information from the original
 * logged event
 *
 * @param definition Definition of the stage
 * @return base::Expression
 */
StageBuilder getParseBuilder(std::shared_ptr<hlp::logpar::Logpar> logpar, size_t debugLvl);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_PARSE_HPP
