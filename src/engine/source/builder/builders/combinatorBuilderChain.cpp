/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "combinatorBuilderChain.hpp"

namespace builder::internals::builders
{

types::Lifter combinatorBuilderChain(const std::vector<types::Lifter> & lifters)
{
    return [=](types::Observable o)
    {
        // this is way better than std::function for 3 reasons: it doesn't
        // require type erasure or memory allocation, it can be constexpr and
        // it works properly with auto (templated) parameters / return type
        auto connect = [](types::Observable o, std::vector<types::Lifter> remaining,
                          auto & connect_ref) -> types::Observable
        {
            types::Lifter current = remaining.front();
            remaining.erase(remaining.begin());
            types::Observable chain = current(o);
            if (remaining.size() == 0)
            {
                return chain;
            }
            return connect_ref(chain, remaining, connect_ref);
        };
        return connect(o, lifters, connect);
    };
}

} // namespace builder::internals::builders
