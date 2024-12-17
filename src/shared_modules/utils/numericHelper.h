/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _NUMERIC_HELPER_H
#define _NUMERIC_HELPER_H

#include <cmath>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    static double floatToDoubleRound(const float number, const int precision)
    {
        const double factor = std::pow(10.0, precision);
        return std::round(number * factor) / factor;
    }
} // namespace Utils

#pragma GCC diagnostic pop

#endif // _NUMERIC_HELPER_H
