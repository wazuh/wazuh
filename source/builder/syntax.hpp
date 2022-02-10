/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYNTAX_H
#define _SYNTAX_H

#include <string>

/**
 * @brief Defines syntax elements.
 *
 * This namespace contains all anchors and syntax elements that identify
 * different objects.
 */
namespace builder::internals::syntax
{

const int REFERENCE_ANCHOR('$');
const int FUNCTION_HELPER_ANCHOR('+');

} // namespace builder::internals::syntax

#endif // _SYNTAX_H
