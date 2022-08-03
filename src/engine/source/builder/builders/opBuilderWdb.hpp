/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_WDB_SYNC_H
#define _OP_BUILDER_WDB_SYNC_H

#include <any>

#include <baseTypes.hpp>

#include "expression.hpp"
#include <utils/stringUtils.hpp>

constexpr std::string_view STREAM_SOCK_PATH = "/tmp/testStream.socket";

namespace builder::internals::builders
{

/**
 * @brief Executes query on WDB returning status ok or not ok.
 * @param definition The filter definition.
 * @return base::Expression true when executes without any problem, false otherwise.
 */
base::Expression opBuilderWdbUpdate(const std::any& definition);

/**
 * @brief Executes query on WDB returning status and payload.
 * @param definition The filter definition.
 * @param tr Tracer
 * @return base::Expression when true returns string of payload, false none.
 */
base::Expression opBuilderWdbQuery(const std::any& definition);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_WDB_SYNC_H
