/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _OP_BUILDER_SCA_DECODER_H
#define _OP_BUILDER_SCA_DECODER_H

#include "builderTypes.hpp"

namespace builder::internals::builders
{

/**
 * @brief Executes query on WDB returning status ok or not ok.
 * @param def Json Doc
 * @param tr Tracer
 * @return base::Lifter true when executes without any problem, false otherwise.
 */
base::Lifter opBuilderSCAdecoder(const base::DocumentValue& def,
                                types::TracerFn tr);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_SCA_DECODER_H
