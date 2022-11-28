#ifndef _OP_BUILDER_LOG_PARSER_H
#define _OP_BUILDER_LOG_PARSER_H

#include <any>
#include <memory>

#include <expression.hpp>
#include <hlp/logpar.hpp>

#include "registry.hpp"

namespace builder::internals::builders
{

/**
 * @brief Builds parsing stage to be able to get information from the original
 * logged event
 *
 * @param definition Definition of the stage
 * @return base::Expression
 */
Builder getOpBuilderLogParser(std::shared_ptr<hlp::logpar::Logpar> logpar);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_LOG_PARSER_H
