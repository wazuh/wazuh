/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * January 19, 2022.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _BUILDER_PATTERN_HPP
#define _BUILDER_PATTERN_HPP

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    /**
     * @brief This class provides a simple interface to construct an object using a Builder pattern.
     *
     * @tparam T Type of the object to be built.
     * @tparam Ts Arguments.
     */
    template<typename T, class... Ts>
    class Builder
    {
    public:
        /**
         * @brief This method is used to build an object.
         *
         * @param args Arguments.
         * @return T Object built.
         */
        static T builder(Ts... args)
        {
            return T(args...); // Default constructor
        }

        /**
         * @brief This method returns a reference to the object.
         * @return T Reference to the object.
         */
        T& build()
        {
            return static_cast<T&>(*this); // Return reference to self
        }
    };
} // namespace Utils

#pragma GCC diagnostic pop

#endif // _BUILDER_PATTERN_HPP
