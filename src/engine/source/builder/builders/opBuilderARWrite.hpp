/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 */

#ifndef _OP_BUILDER_AR_WRITE_H
#define _OP_BUILDER_AR_WRITE_H

#include "builderTypes.hpp"

namespace builder::internals::builders
{

constexpr const char* AR_QUEUE_PATH {"/tmp/ar.sock"};

/**
 * @brief Helper Function that allows to send a message through the AR queue
 */
base::Lifter opBuilderARWrite(const base::DocumentValue& def, types::TracerFn tr);
} // namespace builder::internals::builders

#endif // _OP_BUILDER_AR_WRITE_H
