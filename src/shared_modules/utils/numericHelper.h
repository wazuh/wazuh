/*
 * Wazuh shared modules utils
 * Copyright (C) Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of either the GNU General Public License, version 2, or
 * the GNU Affero General Public License, version 3 or (at your option) any
 * later version, both as published by the Free Software Foundation.
 *
 * SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
 */

#ifndef _NUMERIC_HELPER_H
#define _NUMERIC_HELPER_H

#include <iomanip>
#include <sstream>
#include <string>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static double floatToDoubleRound(const float number, const int precision)
    {
        std::stringstream ssAux;
        ssAux << std::fixed << std::setprecision(precision) << number;
        return std::stod(ssAux.str());
    }
} // namespace Utils

#pragma GCC diagnostic pop

#endif // _NUMERIC_HELPER_H
