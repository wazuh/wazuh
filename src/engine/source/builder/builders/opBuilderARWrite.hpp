/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 */

#ifndef _OP_BUILDER_AR_WRITE_H
#define _OP_BUILDER_AR_WRITE_H

#include <any>

#include <baseTypes.hpp>

#include "expression.hpp"
#include <utils/stringUtils.hpp>

namespace builder::internals::builders
{

constexpr const char* AR_QUEUE_PATH {"/tmp/ar.sock"};

constexpr const char* AR_INVALID_REFERENCE_MSG =
    "Write AR operator: Invalid referenced value.";

/**
 * @brief Helper Function that allows to send a message through the AR queue
 *
 * @param definition The transformation definition. i.e : `<field>: +ar_write/<str>|$<ref>`
 * @return base::Expression The lifter with the `ar_write` transformation.
 */
base::Expression opBuilderARWrite(const std::any& definition);
} // namespace builder::internals::builders

#endif // _OP_BUILDER_AR_WRITE_H
