/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 19, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BUILDER_PATTERN_HPP
#define _BUILDER_PATTERN_HPP

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    template <typename T>
    class Builder
    {
        public:
            static T builder()
            {
                return {}; // Default constructor
            }

            T& build()
            {
                return static_cast<T&>(*this); // Return reference to self
            }
    };
}

#pragma GCC diagnostic pop

#endif // _BUILDER_PATTERN_HPP


