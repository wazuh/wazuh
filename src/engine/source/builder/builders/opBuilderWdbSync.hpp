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

#include "builderTypes.hpp"

constexpr std::string_view STREAM_SOCK_PATH = "/tmp/testStream.socket";

namespace builder::internals::builders
{

/**
 * @brief Executes query on WDB returning status ok or not ok.
 * @param def Json Doc
 * @param tr Tracer
 * @return base::Lifter true when executes without any problem, false otherwise.
 */
base::Lifter opBuilderWdbSyncUpdate(const base::DocumentValue& def,
                                types::TracerFn tr);

/**
 * @brief Executes query on WDB returning status and payload.
 * @param def Json Doc
 * @param tr Tracer
 * @return base::Lifter when true returns string of payload, false none.
 */
base::Lifter opBuilderWdbSyncQuery(const base::DocumentValue& def,
                                   types::TracerFn tr);
} // namespace builder::internals::builders

#endif // _OP_BUILDER_WDB_SYNC_H
