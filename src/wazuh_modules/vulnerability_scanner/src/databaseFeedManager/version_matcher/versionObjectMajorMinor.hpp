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

#ifndef _VERSION_OBJECT_MAJORMINOR_HPP
#define _VERSION_OBJECT_MAJORMINOR_HPP

#include "iVersionObjectInterface.hpp"
#include <iostream>
#include <memory>
#include <regex>
#include <string>

/**
 * @brief MajorMinor data struct.
 *
 */
struct MajorMinor
{
    uint32_t major; ///< Major.
    uint32_t minor; ///< Minor.
};
/**
 * @brief VersionObjectMajorMinor class.
 *
 */
class VersionObjectMajorMinor final : public IVersionObject
{
private:
    static std::regex m_parserRegex;
    uint32_t m_major {};
    uint32_t m_minor {};

public:
    /**
     * @brief Parses a version string and returns a MajorMinor object.
     *
     * @param version version string to parse.
     * @param output MajorMinor object to store the parsed version.
     * @return true/false according to success/failure.
     */
    static bool match(const std::string& version, MajorMinor& output)
    {
        std::smatch parserMatches;
        if ((std::regex_match(version, parserMatches, m_parserRegex) == false) || (parserMatches.size() != 3))
        {
            return false;
        }

        output.major = static_cast<uint32_t>(std::stoul(parserMatches.str(1)));
        output.minor = static_cast<uint32_t>(std::stoul(parserMatches.str(2)));

        return true;
    }

    /**
     * @brief Constructor.
     *
     * @param version version MajorMinor object.
     */
    explicit VersionObjectMajorMinor(const MajorMinor& version)
        : m_major {version.major}
        , m_minor {version.minor}
    {
    }

    // LCOV_EXCL_START
    ~VersionObjectMajorMinor() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Returns the VersionObjectType of this class.
     *
     * @return VersionObjectType.
     */
    VersionObjectType getType() override
    {
        return VersionObjectType::MajorMinor;
    }

    /**
     * @brief Comparison operator ==.
     *
     * @param b comparison rhs object.
     * @return true/false according to equality condition.
     */
    bool operator==(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectMajorMinor*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }
        return (m_major == pB->m_major && m_minor == pB->m_minor);
    }

    /**
     * @brief Comparison operator <.
     *
     * @param b comparison rhs object.
     * @return true/false according to less than condition.
     */
    bool operator<(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectMajorMinor*>(&b);
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

        return m_minor < pB->m_minor;
    }
};

#endif // _VERSION_OBJECT_MAJORMINOR_HPP
