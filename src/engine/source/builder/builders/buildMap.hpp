/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILDERS_MAP_H
#define _BUILDERS_MAP_H

#include <stdexcept>
#include <string>
#include <vector>

#include "json.hpp"
#include "rxcpp/rx.hpp"
#include "syntax.hpp"

namespace builder::internals::builders
{

// The type of the event which will flow through the stream
using Event_t = json::Document;
// The type of the observable which will compose the processing graph
using Obs_t = rxcpp::observable<Event_t>;
// The type of a connectable operation
using Op_t = std::function<Obs_t(const Obs_t &)>;

/**
 * @brief
 *
 * @param def
 * @return Op_t
 */
Op_t buildMapVal(const json::Value & def);

/**
 * @brief
 *
 * @param path
 * @param ref
 * @return Op_t
 */
Op_t buildMapRef(const std::string path, const std::string ref);

/**
 * @brief convers an map-type definition into an operation
 * which will execute all the transofmations defined.
 *
 * @param def definition of the map stage
 * @return Op_t
 */
Op_t buildMap(const json::Value & def);

} // namespace builder::internals::builders

#endif // _BUILDERS_MAP_H
