/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <functional>
#include <rxcpp/rx.hpp>
#include <stdexcept>
#include <vector>
#include <string>

#include "connectable.hpp"
#include "json.hpp"

namespace builder::internals::builders
{
// The type of the event which will flow through the stream
using Event_t = json::Document;
// The type of the observable which will compose the processing graph
using Obs_t = rxcpp::observable<Event_t>;
// The type of the connectables whisch will help us connect the assets ina graph
using Con_t = builder::internals::Connectable<Obs_t>;
// The type of a connectable operation
using Op_t = std::function<Obs_t(const Obs_t &)>;
// The signature of a maker function which will build an asset into a`
// connectable.

using Graph_t = graph::Graph<Con_t>;
}
