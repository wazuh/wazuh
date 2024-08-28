/*
 * Wazuh Vulnerability scanner - Database Feed Manager
 * Copyright (C) 2015, Wazuh Inc.
 * December 14, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _VERSION_OBJECT_RPM_HPP
#define _VERSION_OBJECT_RPM_HPP

#include "iVersionObjectInterface.hpp"
#include <cctype>
#include <cstring>
#include <iostream>
#include <memory>
#include <regex>
#include <string>

static auto constexpr RIGHT_IS_NEWER = -1;
static auto constexpr LEFT_EQ_RIGHT = 0;
static auto constexpr LEFT_IS_NEWER = 1;

/**
 * @brief Rpm data struct.
 *
 */
struct Rpm
{
    uint32_t epoch;      ///< Epoch value.
    std::string version; ///< Version value.
    std::string release; ///< Release value.
};

/**
 * @brief VersionObjectRpm class.
 *
 */
class VersionObjectRpm final : public IVersionObject
{
private:
    static std::regex m_parserRegex;
    uint32_t m_epoch;
    std::string m_version;
    std::string m_release;

    /**
     * @brief Compares two version strings following RPM version comparison rules.
     *
     * This function compares two version strings to determine which version is newer, adhering to the comparison rules
     * used by RPM packages. This ensures compatibility with standard RPM package versioning. The comparison process
     * involves several steps to accurately compare version strings that may include alphanumeric characters and tildes
     * (~).
     *
     * The process begins by checking for string equality. If both version strings are identical, they are considered
     * equal. If not, each string is converted into a list of characters for detailed comparison.
     *
     * The comparison involves the following steps:
     * - First, any leading characters that are neither alphanumeric nor tildes (~) are trimmed from both character
     * lists.
     * - Next, leading tildes (~) are removed. A tilde at the beginning of a version indicates that the version should
     *   be considered older than versions without a tilde, even if numerically larger. Therefore, if one version starts
     *   with a tilde and the other does not, the version without the tilde is considered newer.
     * - The comparison then proceeds by popping and comparing consecutive blocks of digits or letters from the start of
     *   each list. If a difference is found, the comparison result of these blocks is returned immediately.
     * - If all characters are compared without finding a difference, the comparison concludes by examining the lengths
     *   of any remaining characters in the lists. A version with remaining characters is considered newer, unless those
     *   characters begin with a tilde, in which case it is considered older. This step accounts for scenarios where one
     *   version string has been entirely consumed, leaving characters in the other, such as when comparing "1.05b" to
     * "1.05".
     *
     * @param leftVer The left-hand side version string to compare.
     * @param rightVer The right-hand side version string to compare.
     * @return Returns LEFT_IS_NEWER if `leftVer` is considered newer, RIGHT_IS_NEWER if `rightVer` is newer, or
     * LEFT_EQ_RIGHT if both versions are considered the same.
     */

    int rpmvercmp(const std::string& leftVer, const std::string& rightVer) const
    {
        /* easy comparison to see if versions are identical */
        if (leftVer == rightVer)
        {
            return LEFT_EQ_RIGHT;
        }

        auto leftBuffer = leftVer;
        auto rightBuffer = rightVer;
        char* strLeft = leftBuffer.data();
        char* strRight = rightBuffer.data();
        char *auxLeft, *auxRight;
        int resultComparision;
        int isNumber;

        auxLeft = strLeft;
        auxRight = strRight;

        /* loop through each version segment of strLeft and strRight and compare them */
        while (*auxLeft || *auxRight)
        {
            while (*auxLeft && !std::isalnum(*auxLeft) && *auxLeft != '~' && *auxLeft != '^') auxLeft++;
            while (*auxRight && !std::isalnum(*auxRight) && *auxRight != '~' && *auxRight != '^') auxRight++;

            /* handle the tilde separator, it sorts before everything else */
            if (*auxLeft == '~' || *auxRight == '~')
            {
                if (*auxLeft != '~')
                {
                    return LEFT_IS_NEWER;
                }
                if (*auxRight != '~')
                {
                    return RIGHT_IS_NEWER;
                }
                auxLeft++;
                auxRight++;
                continue;
            }

            /*
             * Handle caret separator. Concept is the same as tilde,
             * except that if auxLeft of the strings ends (base version),
             * the other is considered as higher version.
             */
            if (*auxLeft == '^' || *auxRight == '^')
            {
                if (!*auxLeft)
                {
                    return RIGHT_IS_NEWER;
                }
                if (!*auxRight)
                {
                    return LEFT_IS_NEWER;
                }
                if (*auxLeft != '^')
                {
                    return LEFT_IS_NEWER;
                }
                if (*auxRight != '^')
                {
                    return RIGHT_IS_NEWER;
                }
                auxLeft++;
                auxRight++;
                continue;
            }

            /* If we ran to the end of either, we are finished with the loop */
            if (!(*auxLeft && *auxRight))
            {
                break;
            }

            strLeft = auxLeft;
            strRight = auxRight;

            /* grab first completely alpha or completely numeric segment */
            /* leave auxLeft and auxRight pointing to the start of the alpha or numeric */
            /* segment and walk strLeft and strRight to end of segment */
            if (std::isdigit(*strLeft))
            {
                while (*strLeft && std::isdigit(*strLeft)) strLeft++;
                while (*strRight && std::isdigit(*strRight)) strRight++;
                isNumber = LEFT_IS_NEWER;
            }
            else
            {
                while (*strLeft && std::isalpha(*strLeft)) strLeft++;
                while (*strRight && std::isalpha(*strRight)) strRight++;
                isNumber = LEFT_EQ_RIGHT;
            }

            /* save character at the end of the alpha or numeric segment */
            /* so that they can be restored after the comparison */
            const auto oldChrLeft = *strLeft;
            *strLeft = '\0';
            const auto oldChrRight = *strRight;
            *strRight = '\0';

            /* this cannot happen, as we previously tested to make sure that */
            /* the first string has a non-null segment */
            if (auxLeft == strLeft)
            {
                return RIGHT_IS_NEWER; // LCOV_EXCL_LINE
            }

            /* take care of the case where the auxRight version segments are */
            /* different types: auxLeft numeric, the other alpha (i.e. empty) */
            /* numeric segments are always newer than alpha segments */
            /* XXX See patch #60884 (and details) from bugzilla #50977. */
            if (auxRight == strRight)
            {
                return (isNumber ? LEFT_IS_NEWER : RIGHT_IS_NEWER);
            }

            if (isNumber)
            {
                size_t onelen, twolen;
                /* this used to be done by converting the digit segments */
                /* to ints using atoi() - it's changed because long  */
                /* digit segments can overflow an int - this should fix that. */

                /* throw away any leading zeros - it's a number, right? */
                while (*auxLeft == '0') auxLeft++;
                while (*auxRight == '0') auxRight++;

                /* whichever number has more digits wins */
                onelen = std::strlen(auxLeft);
                twolen = std::strlen(auxRight);
                if (onelen > twolen)
                {
                    return LEFT_IS_NEWER;
                }
                if (twolen > onelen)
                {
                    return RIGHT_IS_NEWER;
                }
            }

            /* strcmp will return which auxLeft is greater - even if the auxRight */
            /* segments are alpha or if they are numeric.  don't return  */
            /* if they are equal because there might be more segments to */
            /* compare */
            resultComparision = std::strcmp(auxLeft, auxRight);
            if (resultComparision)
            {
                return (resultComparision < 1 ? RIGHT_IS_NEWER : LEFT_IS_NEWER);
            }

            /* restore character that was replaced by null above */
            *strLeft = oldChrLeft;
            auxLeft = strLeft;
            *strRight = oldChrRight;
            auxRight = strRight;
        }

        /* this catches the case where all numeric and alpha segments have */
        /* compared identically but the segment sepparating characters were */
        /* different */
        if ((!*auxLeft) && (!*auxRight))
        {
            return LEFT_EQ_RIGHT;
        }

        /* whichever version still has characters left over wins */
        if (!*auxLeft)
        {
            return RIGHT_IS_NEWER;
        }
        else
        {
            return LEFT_IS_NEWER;
        }
    }

    /**
     *  Compare auxRight EVR values to determine which is newer
     *
     *  This method compares the epoch, version, and release of the
     *  provided package strings, assuming that epoch is 0 if not provided.
     *  Comparison is performed on the epoch, then the version, and then
     *  the release. If at any point a non-equality is found, the result is
     *  returned without any remaining comparisons being performed (e.g. if
     *  the epochs of the packages differ, the versions are releases are
     *  not compared).
     *
     * @see rpmdev-vercmp(1)
     *
     * @param rEpoch The epoch of the right-hand side package.
     * @param rVersion The version of the right-hand side package.
     * @param rRelease The release of the right-hand side package.
     *
     * @return Returns LEFT_IS_NEWER if `leftVer` is considered newer, RIGHT_IS_NEWER if `rightVer` is newer, or
     * LEFT_EQ_RIGHT if both versions are considered the same.
     */
    int compareRpmVersion(const uint32_t rEpoch, const std::string& rVersion, const std::string& rRelease) const
    {
        // Compare epochs
        if (m_epoch != rEpoch)
        {
            return m_epoch < rEpoch ? RIGHT_IS_NEWER : LEFT_IS_NEWER;
        }

        // If epochs are equal, compare versions.
        const auto verComp = rpmvercmp(m_version, rVersion);

        if (verComp != LEFT_EQ_RIGHT)
        {
            return verComp;
        }

        // If versions are equal, compare releases.
        return rpmvercmp(m_release, rRelease);
    }

public:
    /**
     * @brief Static method to match a version string to a Rpm object.
     *
     * @param version version string to match.
     * @param output Rpm object to store the result.
     * @return true/false according to match condition.
     */
    static bool match(const std::string& version, Rpm& output)
    {
        // Find the position of the colon separator and the hyphen separator
        size_t colonPos = version.find(':');
        size_t hyphenPos = version.find('-');

        // Find and extract the epoch, it's the non-negative value
        // before  :. If is not present, set the default value to zero.
        if (colonPos != std::string::npos)
        {
            output.epoch = std::stoi(version.substr(0, colonPos));
        }
        else
        {
            output.epoch = 0;
            colonPos = 0;
        }

        // Find the version and release, the version is before the hyphen and after the colon,
        // the release is before the hyphen
        const auto versionStart = colonPos == 0 ? colonPos : colonPos + 1;
        const auto versionEnd = hyphenPos == std::string::npos ? version.size() : hyphenPos;
        const auto releaseStart = hyphenPos == std::string::npos ? version.size() : hyphenPos + 1;

        output.version = version.substr(versionStart, versionEnd - versionStart);
        output.release = version.substr(releaseStart);

        return true;
    }

    /**
     * @brief Constructor.
     *
     * @param version version SemVer object.
     */
    explicit VersionObjectRpm(const Rpm& version)
        : m_epoch(version.epoch)
        , m_version(version.version)
        , m_release(version.release)
    {
    }
    // LCOV_EXCL_START
    ~VersionObjectRpm() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Returns the VersionObjectType of this class.
     *
     * @return VersionObjectType.
     */
    VersionObjectType getType() override { return VersionObjectType::RPM; }

    /**
     * @brief Comparison operator ==.
     *
     * @param b comparison rhs object.
     * @return true/false according to equality condition.
     */
    bool operator==(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectRpm*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }

        return compareRpmVersion(pB->m_epoch, pB->m_version, pB->m_release) == LEFT_EQ_RIGHT;
    }

    /**
     * @brief Comparison operator <.
     *
     * @param b comparison rhs object.
     * @return true/false according to less than condition.
     */
    bool operator<(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectRpm*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }

        return compareRpmVersion(pB->m_epoch, pB->m_version, pB->m_release) == RIGHT_IS_NEWER;
    }
};

#endif // _VERSION_OBJECT_RPM_HPP
