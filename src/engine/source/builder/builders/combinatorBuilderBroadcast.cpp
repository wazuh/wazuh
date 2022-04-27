/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "combinatorBuilderBroadcast.hpp"

#include <vector>
namespace builder::internals::builders
{

using base::Lifter;
using base::Observable;
using std::vector;

Lifter combinatorBuilderBroadcast(const vector<Lifter> &lifters)
{
    return [=](Observable input) -> Observable
    {
        vector<Observable> inputs;
        for (auto op : lifters)
        {
            inputs.push_back(op(input));
        }
        return rxcpp::observable<>::iterate(inputs).merge();
    };
}

} // namespace builder::internals::builders
