/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */


#ifndef _OP_BUILDER_HELPER_MAP_H
#define _OP_BUILDER_HELPER_MAP_H

#include "builderTypes.hpp"

/*
 * The helper filter, builds a lifter that will chain rxcpp filter operation
 * Rxcpp transform expects a function that returns event.
 */

namespace builder::internals::builders
{



//*************************************************
//*           String tranform                     *
//*************************************************
// TODO DOCME
types::Event opBuilderHelperStringTransformation(const std::string key, char op, types::Event & e,
                                                 std::optional<std::string> refExpStr,
                                                 std::optional<std::string> expectedStr);

types::Lifter opBuilderHelperString_up(const types::DocumentValue & def);

types::Lifter opBuilderHelperString_lo(const types::DocumentValue & def);

types::Lifter opBuilderHelperString_trim(const types::DocumentValue & def);



} // namespace builder::internals::builders

#endif // _OP_BUILDER_HELPER_MAP_H
