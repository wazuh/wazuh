/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILDERS_CHECK_H
#define _BUILDERS_CHECK_H

#include <stdexcept>
#include <string>
#include <vector>

#include "json.hpp"
#include "rxcpp/rx.hpp"
#include "syntax.hpp"

namespace builder::internals::builders
{
using namespace builder::internals::syntax;

// The type of the event which will flow through the stream
using Event_t = json::Document;
// The type of the observable which will compose the processing graph
using Obs_t = rxcpp::observable<Event_t>;
// The type of a connectable operation
using Op_t = std::function<Obs_t(const Obs_t &)>;

/**
 * @brief
 *
 * @param input
 * @return Obs_t
 */
Obs_t unit_op(Obs_t input);

/**
 * @brief
 *
 * @param def
 * @return Op_t
 */
Op_t buildCheckVal(const json::Value & def);

/**
 * @brief
 *
 * @param path
 * @return Op_t
 */
Op_t buildCheckFH(const std::string path);

/**
 * @brief
 *
 * @param path
 * @param ref
 * @return Op_t
 */
Op_t buildCheckRef(const std::string path, const std::string ref);

/**
 * @brief Builds check operations
 *
 * @param input_observable
 * @param input_json
 * @return Op_t
 */
Op_t buildCheck(const json::Value & def);

} // namespace builder::internals::builders

#endif // _BUILDERS_CHECK_H
