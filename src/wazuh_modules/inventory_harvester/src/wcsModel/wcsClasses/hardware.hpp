/*
 * Wazuh inventory harvester
 * Copyright (C) 2015, Wazuh Inc.
 * March 20, 2025.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HW_WCS_MODEL_HPP
#define _HW_WCS_MODEL_HPP

#include "reflectiveJson.hpp"
#include <string_view>

struct Hardware final
{
    struct CPU final
    {
        int64_t cores;
        std::string_view name;
        int64_t speed;

        REFLECTABLE(MAKE_FIELD("cores", &CPU::cores), MAKE_FIELD("name", &CPU::name), MAKE_FIELD("speed", &CPU::speed));
    } cpu;
    struct Memory final
    {
        int64_t free;
        int64_t total;
        int64_t used;

        REFLECTABLE(MAKE_FIELD("free", &Memory::free),
                    MAKE_FIELD("total", &Memory::total),
                    MAKE_FIELD("used", &Memory::used));
    } memory;

    REFLECTABLE(MAKE_FIELD("cpu", &Hardware::cpu), MAKE_FIELD("memory", &Hardware::memory));
};

#endif // _HW_WCS_MODEL_HPP
