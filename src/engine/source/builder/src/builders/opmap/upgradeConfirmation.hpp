#ifndef _OP_BUILDER_HELPER_UPGRADE_CONFIRMATION_H
#define _OP_BUILDER_HELPER_UPGRADE_CONFIRMATION_H

#include <sockiface/isockFactory.hpp>

#include "builders/types.hpp"

namespace builder::builders::opmap
{

constexpr const char* WM_UPGRADE_SOCK {"/var/ossec/queue/tasks/upgrade"};

/**
 * @brief Sends upgrade confirmation throug UPGRADE_MQ socket
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression The ifter with the transformation.
 */
MapBuilder getUpgradeConfirmationBUilder(const std::shared_ptr<sockiface::ISockFactory>& sockFactory);

} // namespace builder::builders::opmap

#endif // _OP_BUILDER_HELPER_UPGRADE_CONFIRMATION_H
