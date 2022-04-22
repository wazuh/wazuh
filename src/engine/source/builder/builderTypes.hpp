/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILDER_TYPES_H
#define _BUILDER_TYPES_H

#include <functional>
#include <variant>
#include <vector>
#include <memory>

#include <rxcpp/rx.hpp>

//#include <eventHandler.hpp>
#include <baseTypes.hpp>
#include "connectable.hpp"

/**
 * @brief Type definitions needed by builders
 *
 */
namespace builder::internals::types
{
using ConnectableT = Connectable<base::Observable>;
using AssetBuilder = std::function<ConnectableT(const base::Document &)>;
using TracerFn = std::function<void(std::string)>;
using OpBuilder = std::function<base::Lifter(const base::DocumentValue &, TracerFn)>;
using CombinatorBuilder = std::function<base::Lifter(std::vector<base::Lifter>)>;
using BuilderVariant = std::variant<AssetBuilder, OpBuilder, CombinatorBuilder>;

} // namespace builder::internals::types

#endif // _BUILDER_TYPES_H
