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

#ifndef _VERSION_OBJECT_CALVER_HPP
#define _VERSION_OBJECT_CALVER_HPP

#include "iVersionObjectInterface.hpp"
#include <iostream>
#include <memory>
#include <regex>
#include <string>

/**
 * @brief CalVer data struct.
 *
 */
struct CalVer
{
    uint16_t year;  ///< Year.
    uint8_t month;  ///< Month.
    uint8_t day;    ///< Day.
    uint32_t micro; ///< Microseconds.
};

/**
 * @brief VersionObjectCalVer class.
 *
 */
class VersionObjectCalVer final : public IVersionObject
{
private:
    static std::regex m_parserRegex;
    uint16_t m_year;
    uint8_t m_month;
    uint8_t m_day;
    uint32_t m_micro;

public:
    /**
     * @brief Parses a version string and returns a CalVer object.
     *
     * @param version version string to parse.
     * @param output CalVer object to store the parsed version.
     * @return true/false according to success/failure.
     */
    static bool match(const std::string& version, CalVer& output)
    {
        std::smatch parserMatches;
        if ((std::regex_match(version, parserMatches, m_parserRegex) == false) || (parserMatches.size() != 5))
        {
            return false;
        }

        output.year = (parserMatches.str(1).size() == 2)
                          ? static_cast<uint16_t>(std::stoul(parserMatches.str(1))) + 2000
                          : static_cast<uint16_t>(std::stoul(parserMatches.str(1)));

        if (!parserMatches.str(2).empty())
        {
            output.month = static_cast<uint8_t>(std::stoul(parserMatches.str(2).substr(1)));
            if (output.month < 1 || output.month > 12)
            {
                return false;
            }
        }
        else
        {
            output.month = 0;
        }

        if (!parserMatches.str(3).empty())
        {
            output.day = static_cast<uint8_t>(std::stoul(parserMatches.str(3).substr(1)));
            if (output.day < 1 || output.day > 31)
            {
                return false;
            }
        }
        else
        {
            output.day = 0;
        }

        output.micro =
            parserMatches.str(4).empty() ? 0 : static_cast<uint32_t>(std::stoul(parserMatches.str(4).substr(1)));

        return true;
    }

    /**
     * @brief Constructor.
     *
     * @param version CalVer object.
     */
    explicit VersionObjectCalVer(const CalVer& version)
        : m_year {version.year}
        , m_month {version.month}
        , m_day {version.day}
        , m_micro {version.micro}
    {
    }

    // LCOV_EXCL_START
    ~VersionObjectCalVer() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Returns the VersionObjectType of this class.
     *
     * @return VersionObjectType.
     */
    VersionObjectType getType() override { return VersionObjectType::CalVer; }

    /**
     * @brief Comparison operator ==.
     *
     * @param b comparison rhs object.
     * @return true/false according to equality condition.
     */
    bool operator==(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectCalVer*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }
        return (m_year == pB->m_year && m_month == pB->m_month && m_day == pB->m_day && m_micro == pB->m_micro);
    }

    /**
     * @brief Comparison operator <.
     *
     * @param b comparison rhs object.
     * @return true/false according to less than condition.
     */
    bool operator<(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectCalVer*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }

        if (m_year < pB->m_year)
        {
            return true;
        }
        else if (m_year > pB->m_year)
        {
            return false;
        }

        if (m_month < pB->m_month)
        {
            return true;
        }
        else if (m_month > pB->m_month)
        {
            return false;
        }

        if (m_day < pB->m_day)
        {
            return true;
        }
        else if (m_day > pB->m_day)
        {
            return false;
        }

        return m_micro < pB->m_micro;
    }
};

#endif // _VERSION_OBJECT_CALVER_HPP
