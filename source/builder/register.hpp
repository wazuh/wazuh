/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTER_HPP
#define _REGISTER_HPP

#include "registry.hpp"
#include <variant>

// Add all builders includes here
#include "buildCheck.hpp"

namespace builder::internals
{
void registerBuilders()
{
    // Needed to initialize the variant type
    BuildValue b;
    BuildType c;

    // Register all builders
    // Condition Value
    b = builders::buildCheckVal;
    c = b;
    Registry::registerBuilder("condition.value", c);

    // Condition
    b = builders::buildCheck;
    c = b;
    Registry::registerBuilder("condition", c);
}
} // namespace builder::internals

#endif // _REGISTER_HPP
