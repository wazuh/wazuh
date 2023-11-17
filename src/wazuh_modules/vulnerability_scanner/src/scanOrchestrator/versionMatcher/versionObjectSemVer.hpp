/*
 * Wazuh Vulnerability scanner - Database Feed Manager
 * Copyright (C) 2015, Wazuh Inc.
 * November 3, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _VERSION_OBJECT_SEMVER_HPP
#define _VERSION_OBJECT_SEMVER_HPP

#include "iVersionObjectInterface.hpp"
#include <iostream>
#include <memory>
#include <regex>
#include <string>

/**
 * @brief SemVer data struct.
 *
 */
struct SemVer
{
    uint32_t major;            ///< Major.
    uint32_t minor;            ///< Minor.
    uint32_t patch;            ///< Patch.
    std::string preRelease;    ///< Pre-release.
    std::string buildMetadata; ///< Build metadata.
};

/**
 * @brief VersionObjectSemVer class.
 *
 */
class VersionObjectSemVer final : public IVersionObject
{
private:
    static std::regex m_parserRegex;
    uint32_t m_major;
    uint32_t m_minor;
    uint32_t m_patch;
    std::string m_preRelease;
    std::string m_buildMetadata;

public:
    /**
     * @brief Static method to match a version string to a SemVer object.
     *
     * @param version version string to match.
     * @param output SemVer object to store the result.
     * @return true/false according to match condition.
     */
    static bool match(const std::string& version, SemVer& output)
    {
        std::smatch parserMatches;
        if ((std::regex_match(version, parserMatches, m_parserRegex) == false) || (parserMatches.size() != 6))
        {
            return false;
        }

        output.major = static_cast<uint32_t>(std::stoul(parserMatches.str(1)));
        output.minor = static_cast<uint32_t>(std::stoul(parserMatches.str(2)));
        output.patch = static_cast<uint32_t>(std::stoul(parserMatches.str(3)));
        output.preRelease = parserMatches[4];
        output.buildMetadata = parserMatches[5];

        return true;
    }
    /**
     * @brief Constructor.
     *
     * @param version version SemVer object.
     */
    explicit VersionObjectSemVer(const SemVer& version)
        : m_major {version.major}
        , m_minor {version.minor}
        , m_patch {version.patch}
        , m_preRelease {version.preRelease}
        , m_buildMetadata {version.buildMetadata}
    {
    }
    // LCOV_EXCL_START
    ~VersionObjectSemVer() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Returns the VersionObjectType of this class.
     *
     * @return VersionObjectType.
     */
    VersionObjectType getType() override
    {
        return VersionObjectType::SemVer;
    }

    /**
     * @brief Comparison operator ==.
     *
     * @param b comparison rhs object.
     * @return true/false according to equality condition.
     */
    bool operator==(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectSemVer*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }
        return (m_major == pB->m_major && m_minor == pB->m_minor && m_patch == pB->m_patch &&
                m_preRelease == pB->m_preRelease);
    }

    /**
     * @brief Comparison operator <.
     *
     * @param b comparison rhs object.
     * @return true/false according to less than condition.
     */
    bool operator<(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectSemVer*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }

        if (m_major < pB->m_major)
        {
            return true;
        }
        else if (m_major > pB->m_major)
        {
            return false;
        }

        if (m_minor < pB->m_minor)
        {
            return true;
        }
        else if (m_minor > pB->m_minor)
        {
            return false;
        }

        if (m_patch < pB->m_patch)
        {
            return true;
        }
        else if (m_patch > pB->m_patch)
        {
            return false;
        }

        if (!m_preRelease.empty() && pB->m_preRelease.empty())
        {
            return true;
        }
        else if (!m_preRelease.empty() && !pB->m_preRelease.empty())
        {
            if (m_preRelease.compare(pB->m_preRelease) < 0)
            {
                return true;
            }
        }

        return false;
    }
};

#endif // _VERSION_OBJECT_SEMVER_HPP
