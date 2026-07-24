/*
 * Wazuh agent HTTPS client (C++ transport module)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sysSeams.hpp"

#include <cstdio>

std::time_t SystemClock::wallSeconds() const
{
    return std::time(nullptr);
}

std::chrono::steady_clock::time_point SystemClock::steadyNow() const
{
    return std::chrono::steady_clock::now();
}

Mt19937Random::Mt19937Random()
    : m_engine(std::random_device {}())
{
}

double Mt19937Random::uniform01()
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return std::uniform_real_distribution<double> {0.0, 1.0}(m_engine);
}

bool FsProbe::isReadableFile(const std::string& path) const
{
    std::FILE* file = std::fopen(path.c_str(), "rb");

    if (file == nullptr)
    {
        return false;
    }

    std::fclose(file);
    return true;
}
