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

namespace builder::internals::builders
{
/**
 * @brief 
 * @param def 
 * @param tr 
 * @return base::Lifter 
 */
base::Lifter opBuilderWdbSyncUpdate(const base::DocumentValue& def,
                                types::TracerFn tr);

/**
 * @brief Builds KVDB extract function helper
 *
 * @param def
 * @return base::Lifter
 */
base::Lifter opBuilderWdbSyncQuery(const base::DocumentValue& def,
                                   types::TracerFn tr);

/**
 * @brief 
 * 
 * @param def 
 * @param tr 
 * @param returnPayload 
 * @return base::Lifter 
 */
base::Lifter opBuilderWdbSyncGenericQuery(const base::DocumentValue& def,
                                   types::TracerFn tr, bool returnPayload = true);
} // namespace builder::internals::builders

#endif // _OP_BUILDER_WDB_SYNC_H
