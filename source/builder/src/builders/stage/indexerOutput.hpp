#ifndef _BUILDER_BUILDERS_STAGE_INDEXEROUTPUT_HPP
#define _BUILDER_BUILDERS_STAGE_INDEXEROUTPUT_HPP

#include <fstream>
#include <iostream>
#include <string>

#include <fmt/format.h>

#include <indexerConnector/iindexerconnector.hpp>

#include "builders/types.hpp"

namespace builder::builders
{

/**
 * @brief Build the indexer output stage.
 *
 * @param definition Json definition of the stage.
 * @param buildCtx Build context.
 * @param indexerPtr Indexer connector.
 * @return base::Expression The built stage expression.
 */
base::Expression indexerOutputBuilder(const json::Json& definition,
                                      const std::shared_ptr<const IBuildCtx>& buildCtx,
                                      const std::shared_ptr<IIndexerConnector>& indexerPtr);

/**
 * @brief Get the Indexer Output Stage Builder.
 *
 * @param indexerPtr Indexer connector.
 * @return StageBuilder The indexer output builder.
 */
StageBuilder getIndexerOutputBuilder(const std::shared_ptr<IIndexerConnector>& indexerPtr);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_STAGE_INDEXEROUTPUT_HPP
