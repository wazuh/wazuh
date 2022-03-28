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

#include "connectable.hpp"
#include "json.hpp"

/**
 * @brief Type definitions needed by builders
 *
 */
namespace builder::internals::types
{

using Event = std::shared_ptr<json::Document>;
using Document = json::Document;
using DocumentValue = json::Value;
using Observable = rxcpp::observable<Event>;
using Lifter = std::function<Observable(Observable)>;
using ConnectableT = Connectable<Observable>;
using AssetBuilder = std::function<ConnectableT(const Document &)>;
using TracerFn = std::function<void(std::string)>;
using OpBuilder = std::function<Lifter(const DocumentValue &, TracerFn)>;
using CombinatorBuilder = std::function<Lifter(std::vector<Lifter>)>;
using BuilderVariant = std::variant<AssetBuilder, OpBuilder, CombinatorBuilder>;

} // namespace builder::internals::types

#endif // _BUILDER_TYPES_H
