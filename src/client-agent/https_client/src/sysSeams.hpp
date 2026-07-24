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

#ifndef _HC_SYS_SEAMS_HPP
#define _HC_SYS_SEAMS_HPP

#include <chrono>
#include <ctime>
#include <mutex>
#include <random>
#include <string>

/// Wall + monotonic time source. Injected so tests control signing timestamps
/// and cadence decisions deterministically.
class IClock
{
    public:
        virtual ~IClock() = default;
        virtual std::time_t wallSeconds() const = 0;
        virtual std::chrono::steady_clock::time_point steadyNow() const = 0;
};

/// Uniform randomness source for the full-jitter backoff.
class IRandom
{
    public:
        virtual ~IRandom() = default;
        virtual double uniform01() = 0;
};

/// Filesystem probe used by the fail-closed TLS validation.
class IFsProbe
{
    public:
        virtual ~IFsProbe() = default;
        virtual bool isReadableFile(const std::string& path) const = 0;
};

class SystemClock final : public IClock
{
    public:
        std::time_t wallSeconds() const override;
        std::chrono::steady_clock::time_point steadyNow() const override;
};

class Mt19937Random final : public IRandom
{
    public:
        Mt19937Random();
        double uniform01() override;

    private:
        std::mutex m_mutex;
        std::mt19937_64 m_engine;
};

class FsProbe final : public IFsProbe
{
    public:
        bool isReadableFile(const std::string& path) const override;
};

#endif // _HC_SYS_SEAMS_HPP
