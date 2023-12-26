#ifndef _OP_BUILDER_ACTIVE_RESPONSE_HPP
#define _OP_BUILDER_ACTIVE_RESPONSE_HPP

#include <sockiface/isockFactory.hpp>


#include "builders/types.hpp"

namespace builder::builders
{

/**
 * @brief Helper Function that allows to send a message through the AR queue.
 *
 * @param sockFactory
 * @param opArgs
 * @param buildCtx
 * @return TransformOp
 */
MapOp SendAR(std::shared_ptr<sockiface::ISockFactory> sockFactory,
             const std::vector<OpArg>& opArgs,
             const std::shared_ptr<const IBuildCtx>& buildCtx);

MapBuilder getOpBuilderSendAr(std::shared_ptr<sockiface::ISockFactory> sockFactory);

/**
 * @brief Helper Function for creating the base event that will be sent through  * Active Response socket with
 * active_response_send
 *
 *
 * ar_message: +active_response_create/<command-name>/<location>/<timeout>/<extra-args>
 *  - <command-name> (mandatory) It can be set directly or through a reference.
 *  - <location>     (mandatory) Accepted values are: "LOCAL", "ALL" or a specific agent
 * id. Such values can be passed directly or through a reference.
 *  - <timeout>      (optional) Timeout value in seconds. It can be passed directly or
 * through a reference.
 *  - <extra-args>   (optional) Reference to an array of *strings*.
 *
 * @param sockFactory
 * @param opArgs
 * @param buildCtx
 * @return MapOp
 */
MapOp CreateARBuilder(const std::vector<OpArg>& opArgs, const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders

#endif // _OP_BUILDER_ACTIVE_RESPONSE_HPP