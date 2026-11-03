/*
 * Wazuh SysInfo
 * Copyright (C) Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _SYS_OS_PARSERS_H
#define _SYS_OS_PARSERS_H

#include <istream>
#include <string>
#include "json.hpp"
#include "stringHelper.h"

struct ISysOsParser
{
    // LCOV_EXCL_START
    virtual ~ISysOsParser() = default;
    // LCOV_EXCL_STOP
    virtual bool parseFile(std::istream& /*in*/, nlohmann::json& /*output*/)
    {
        return false;
    }
    virtual bool parseUname(const std::string& /*in*/, nlohmann::json& /*output*/)
    {
        return false;
    }
};

class UnixOsParser : public ISysOsParser
{
    public:
        UnixOsParser() = default;
        ~UnixOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class UbuntuOsParser : public ISysOsParser
{
    public:
        UbuntuOsParser() = default;
        ~UbuntuOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class CentosOsParser : public ISysOsParser
{
    public:
        CentosOsParser() = default;
        ~CentosOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class BSDOsParser : public ISysOsParser
{
    public:
        BSDOsParser() = default;
        ~BSDOsParser() = default;
        bool parseUname(const std::string& in, nlohmann::json& output) override;
};

class RedHatOsParser : public ISysOsParser
{
    public:
        RedHatOsParser() = default;
        ~RedHatOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class DebianOsParser : public ISysOsParser
{
    public:
        DebianOsParser() = default;
        ~DebianOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class ArchOsParser : public ISysOsParser
{
    public:
        ArchOsParser() = default;
        ~ArchOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class SlackwareOsParser : public ISysOsParser
{
    public:
        SlackwareOsParser() = default;
        ~SlackwareOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class GentooOsParser : public ISysOsParser
{
    public:
        GentooOsParser() = default;
        ~GentooOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class SuSEOsParser : public ISysOsParser
{
    public:
        SuSEOsParser() = default;
        ~SuSEOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class FedoraOsParser : public ISysOsParser
{
    public:
        FedoraOsParser() = default;
        ~FedoraOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class AlpineOsParser : public ISysOsParser
{
    public:
        AlpineOsParser() = default;
        ~AlpineOsParser() = default;
        bool parseFile(std::istream& in, nlohmann::json& output) override;
};

class MacOsParser
{
    public:
        MacOsParser() = default;
        ~MacOsParser() = default;
        static bool parseSwVersion(const std::string& in, nlohmann::json& output);
        static bool parseSystemProfiler(const std::string& in, nlohmann::json& output);
        static bool parseUname(const std::string& in, nlohmann::json& output);
};

/**
 * @brief Fills os_full with the OS name followed by its version, unless it is already set.
 *
 * Header-only, as SysInfo::os() calls it on every platform and this file's source is not built on
 * Windows, where the provider sets os_full itself.
 *
 * @param output OS information with os_name and os_version.
 */
inline void setOsFull(nlohmann::json& output)
{
    if (!output.is_object() || output.contains("os_full"))
    {
        return;
    }

    const auto getValue = [&output](const std::string & key)
    {
        return output.contains(key) && output[key].is_string() ? Utils::trim(output[key].get<std::string>()) : std::string{};
    };
    const auto name{getValue("os_name")};
    const auto version{getValue("os_version")};

    if (!name.empty())
    {
        output["os_full"] = version.empty() ? name : name + " " + version;
    }
}

class FactorySysOsParser final
{
    public:
        static std::unique_ptr<ISysOsParser> create(const std::string& platform)
        {
            if (platform == "ubuntu")
            {
                return std::make_unique<UbuntuOsParser>();
            }

            if (platform == "centos")
            {
                return std::make_unique<CentosOsParser>();
            }

            if (platform == "unix")
            {
                return std::make_unique<UnixOsParser>();
            }

            if (platform == "bsd")
            {
                return std::make_unique<BSDOsParser>();
            }

            if (platform == "fedora")
            {
                return std::make_unique<FedoraOsParser>();
            }

            if (platform == "debian")
            {
                return std::make_unique<DebianOsParser>();
            }

            if (platform == "gentoo")
            {
                return std::make_unique<GentooOsParser>();
            }

            if (platform == "slackware")
            {
                return std::make_unique<SlackwareOsParser>();
            }

            if (platform == "suse")
            {
                return std::make_unique<SuSEOsParser>();
            }

            if (platform == "arch")
            {
                return std::make_unique<ArchOsParser>();
            }

            if (platform == "rhel")
            {
                return std::make_unique<RedHatOsParser>();
            }

            if (platform == "alpine")
            {
                return std::make_unique<AlpineOsParser>();
            }

            throw std::runtime_error
            {
                "Unsupported platform."
            };
        }
};

#endif //_SYS_OS_PARSERS_H
