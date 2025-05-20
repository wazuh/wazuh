/*
 * Wazuh Vulnerability scanner - Database Feed Manager
 * Copyright (C) 2015, Wazuh Inc.
 * December 06, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _VERSION_OBJECT_DPKG_HPP
#define _VERSION_OBJECT_DPKG_HPP

#include "base/logging.hpp"
#include "iVersionObjectInterface.hpp"
//#include "base/utils/stringUtils.hpp"
//#include "vulnerabilityScannerDefs.hpp"
#include <cctype>
#include <climits>
#include <cstring>
#include <string>

/**
 * @brief Dpkg data struct.
 *
 */
struct Dpkg
{
    uint32_t epoch;       ///< Epoch.
    std::string version;  ///< Version.
    std::string revision; ///< Revision.
};

/**
 * @brief VersionObjectDpkg class.
 *
 */
class VersionObjectDpkg final : public IVersionObject
{
private:
    long m_epoch;
    std::string m_version;
    std::string m_revision;

    /**
     * Give a weight to the character to order in the version comparison.
     *
     * @param chr An ASCII character.
     */
    int order(char chr) const
    {
        if (std::isdigit(chr))
        {
            return 0;
        }
        else if (std::isalpha(chr))
        {
            return chr;
        }
        else if (chr == '~')
        {
            return -1;
        }
        else if (chr)
        {
            return chr + 256;
        }
        else
        {
            return 0;
        }
    }

    /**
     * Make the version comparison with the upstream version and the debian revision.
     *
     * @param leftSide An array of characters.
     * @param rightSide An array of characters.
     */
    int compareVersionAndRevision(const char* leftSide, const char* rightSide) const
    {
        if (leftSide == nullptr)
        {
            leftSide = "";
        }
        if (rightSide == nullptr)
        {
            rightSide = "";
        }

        while (*leftSide || *rightSide)
        {
            int firstDiff = 0;

            while ((*leftSide && !std::isdigit(*leftSide)) || (*rightSide && !std::isdigit(*rightSide)))
            {
                int firstAux = order(*leftSide);
                int secondAux = order(*rightSide);

                if (firstAux != secondAux)
                    return firstAux - secondAux;

                leftSide++;
                rightSide++;
            }
            while (*leftSide == '0') leftSide++;
            while (*rightSide == '0') rightSide++;
            while (std::isdigit(*leftSide) && std::isdigit(*rightSide))
            {
                if (!firstDiff)
                    firstDiff = *leftSide - *rightSide;
                leftSide++;
                rightSide++;
            }

            if (std::isdigit(*leftSide))
                return 1;
            if (std::isdigit(*rightSide))
                return -1;
            if (firstDiff)
                return firstDiff;
        }

        return 0;
    }

    /**
     * Compares two Debian versions.
     *
     * This function follows the convention of the comparator functions used by
     * qsort().
     *
     * @see deb-version(5)
     *
     * @param rEpoch The second epoch.
     * @param rVersion The second version.
     * @param rRevision The second revision.
     *
     * @retval 0 If a and b are equal.
     * @retval <0 If a is smaller than b.
     * @retval >0 If a is greater than b.
     */
    int compareDpkgVersion(const long rEpoch, const std::string& rVersion, const std::string& rRevision) const
    {
        if (m_epoch > rEpoch)
            return 1;
        if (m_epoch < rEpoch)
            return -1;

        auto result = compareVersionAndRevision(m_version.c_str(), rVersion.c_str());
        if (result)
            return result;

        return compareVersionAndRevision(m_revision.c_str(), rRevision.c_str());
    }

public:
    /**
     * @brief Static method to match a version string to a Dpkg object.
     *
     * @param version version string to match.
     * @param output Dpkg object to store the result.
     * @return true/false according to match condition.
     */
    static bool match(const std::string& version, Dpkg& output)
    {
        const char *end, *ptr;
        const char* string = version.c_str();

        /* Trim leading and trailing space. */
        while (*string && std::isspace(*string)) string++;

        if (!*string)
        {
            return false;
        }

        /* String now points to the first non-whitespace char. */
        end = string;
        /* Find either the end of the string, or a whitespace char. */
        while (*end && !std::isspace(*end)) end++;
        /* Check for extra chars after trailing space. */
        ptr = end;
        while (*ptr && std::isspace(*ptr)) ptr++;
        if (*ptr)
        {
            return false;
        }

        auto colon = std::strchr(string, ':');
        if (colon != nullptr)
        {
            long epoch;
            char* eepochcolon;

            errno = 0;
            epoch = std::strtol(string, &eepochcolon, 10);
            if (string == eepochcolon)
            {
                return false;
            }
            if (colon != eepochcolon)
            {
                return false;
            }
            if (epoch < 0)
            {
                return false;
            }
            if (epoch > INT_MAX || errno == ERANGE)
            {
                return false;
            }
            if (!*++colon)
            {
                return false;
            }
            string = colon;
            output.epoch = epoch;
        }
        else
        {
            output.epoch = 0;
        }
        output.version = std::string(string, end - string);

        auto hyphen = const_cast<char*>(std::strchr(output.version.c_str(), '-'));
        if (hyphen != nullptr)
        {
            *hyphen++ = '\0';
            if (*hyphen == '\0')
            {
                return false;
            }
        }
        output.revision = hyphen ? std::string(hyphen) : "";

        /* XXX: Would be faster to use something like cisversion and cisrevision. */
        ptr = output.version.c_str();
        if (!*ptr)
        {
            return false;
        }
        if (!std::isdigit(*ptr++))
        {
            return false;
        }
        for (; *ptr; ptr++)
        {
            if (!std::isdigit(*ptr) && !std::isalpha(*ptr) && strchr(".-+~:", *ptr) == nullptr)
            {
                LOG_DEBUG("Invalid character in revision: {} in {}.", output.version, version);
            }
        }
        for (ptr = output.revision.c_str(); *ptr; ptr++)
        {
            if (!std::isdigit(*ptr) && !std::isalpha(*ptr) && strchr(".+~", *ptr) == nullptr)
            {
                LOG_DEBUG("Invalid character in revision: {} in {}.", output.revision, version);
            }
        }

        return true;
    }
    /**
     * @brief Constructor.
     *
     * @param version version SemVer object.
     */
    explicit VersionObjectDpkg(const Dpkg& version)
        : m_epoch {version.epoch}
        , m_version {version.version}
        , m_revision {version.revision}
    {
    }
    // LCOV_EXCL_START
    ~VersionObjectDpkg() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Returns the VersionObjectType of this class.
     *
     * @return VersionObjectType.
     */
    VersionObjectType getType() override { return VersionObjectType::DPKG; }

    /**
     * @brief Comparison operator ==.
     *
     * @param b comparison rhs object.
     * @return true/false according to equality condition.
     */
    bool operator==(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectDpkg*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }
        return compareDpkgVersion(pB->m_epoch, pB->m_version, pB->m_revision) == 0;
    }

    /**
     * @brief Comparison operator <.
     *
     * @param b comparison rhs object.
     * @return true/false according to less than condition.
     */
    bool operator<(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectDpkg*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }
        return compareDpkgVersion(pB->m_epoch, pB->m_version, pB->m_revision) < 0;
    }
};

#endif // _VERSION_OBJECT_DPKG_HPP
