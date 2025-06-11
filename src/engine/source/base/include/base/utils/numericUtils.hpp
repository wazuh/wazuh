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

#ifndef _NUMERIC_UTILS_HPP
#define _NUMERIC_UTILS_HPP

#include <iomanip>
#include <sstream>
#include <string>

namespace base::utils::numeric
{
static double floatToDoubleRound(const float number, const int precision)
{
    std::stringstream ssAux;
    ssAux << std::fixed << std::setprecision(precision) << number;
    return std::stod(ssAux.str());
}
} // namespace base::utils::numeric

#endif // _NUMERIC_UTILS_HPP
