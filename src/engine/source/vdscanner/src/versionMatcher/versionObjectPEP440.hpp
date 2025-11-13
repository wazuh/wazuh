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

#ifndef _VERSION_OBJECT_PEP440_HPP
#define _VERSION_OBJECT_PEP440_HPP

#include "iVersionObjectInterface.hpp"
#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <memory>
#include <regex>
#include <string>

/**
 * @brief PEP440 data struct.
 *
 */
struct PEP440
{
    uint32_t epoch;             ///< Epoch.
    std::string versionStr;     ///< Version string.
    std::string preReleaseStr;  ///< Pre-release string.
    uint32_t preReleaseNumber;  ///< Pre-release number.
    uint32_t postReleaseNumber; ///< Post-release number.
    uint32_t devReleaseNumber;  ///< Dev-release number.
    bool hasPreRelease;         ///< Has pre-release.
    bool hasPostRelease;        ///< Has post-release.
    bool hasDevRelease;         ///< Has dev-release.
};

/**
 * @brief VersionObjectPEP440 class.
 *
 */
class VersionObjectPEP440 final : public IVersionObject
{
private:
    static std::regex m_parserRegex;
    static std::regex m_parserVersionStrRegex;
    uint32_t m_epoch;
    std::string m_versionStr;
    std::string m_preReleaseStr;
    uint32_t m_preReleaseNumber;
    uint32_t m_postReleaseNumber;
    uint32_t m_devReleaseNumber;
    bool m_hasPreRelease;
    bool m_hasPostRelease;
    bool m_hasDevRelease;

    /**
     * @brief Comparison method for the versionStr variable members.
     *
     * @param versionStrA versionStr member of object A.
     * @param versionStrB versionStr member of object B.
     * @return 0  if A is equal to B.
     *         -1 if A is less than B.
     *         1  if A is greater than B.
     */
    static int compareVersionStr(const std::string& versionStrA, const std::string& versionStrB)
    {
        std::deque<uint32_t> versionStrSplitA;
        std::sregex_token_iterator itA(versionStrA.begin(), versionStrA.end(), m_parserVersionStrRegex, -1);
        std::sregex_token_iterator itEndA;
        while (itA != itEndA)
        {
            versionStrSplitA.push_back(static_cast<uint32_t>(std::stoul(itA->str())));
            itA++;
        }

        std::deque<uint32_t> versionStrSplitB;
        std::sregex_token_iterator itB(versionStrB.begin(), versionStrB.end(), m_parserVersionStrRegex, -1);
        std::sregex_token_iterator itEndB;
        while (itB != itEndB)
        {
            versionStrSplitB.push_back(static_cast<uint32_t>(std::stoul(itB->str())));
            itB++;
        }

        while (versionStrSplitA.size() < versionStrSplitB.size())
        {
            versionStrSplitA.push_back(0);
        }

        while (versionStrSplitB.size() < versionStrSplitA.size())
        {
            versionStrSplitB.push_back(0);
        }

        for (size_t itemIdx = 0; itemIdx < versionStrSplitA.size(); itemIdx++)
        {
            if (versionStrSplitA[itemIdx] < versionStrSplitB[itemIdx])
            {
                return -1;
            }
            if (versionStrSplitA[itemIdx] > versionStrSplitB[itemIdx])
            {
                return 1;
            }
        }

        return 0;
    }

public:
    /**
     * @brief Match string for PEP440 version.
     * @param version version string to match.
     * @param data PEP440 struct.
     *
     * @return bool true if match, false otherwise.
     */
    static bool match(std::string version, PEP440& data)
    {
        // Transform the string to lowercase in-place
        std::transform(
            version.begin(), version.end(), version.begin(), [](unsigned char c) { return std::tolower(c); });

        // Remove leading 'v' if present
        if (!version.empty() && version[0] == 'v')
        {
            version.erase(version.begin());
        }

        size_t pos = 0;

        // Parse epoch safely, ensure it is a number
        size_t exclamationPos = version.find('!');
        if (exclamationPos != std::string::npos)
        {
            if (exclamationPos == 0 || exclamationPos >= version.size())
            {
                return false; // Invalid epoch (empty or misplaced '!')
            }
            std::string epochStr = version.substr(0, exclamationPos);
            if (std::all_of(epochStr.begin(), epochStr.end(), ::isdigit))
            {
                data.epoch = std::stoul(epochStr);
            }
            else
            {
                return false; // Invalid epoch format
            }
            pos = exclamationPos + 1;
        }
        else
        {
            data.epoch = 0;
        }

        // Parse release version
        size_t start = pos;
        while (pos < version.size() && (std::isdigit(version[pos]) || version[pos] == '.'))
        {
            ++pos;
        }

        if (start == pos)
        {
            return false; // No valid release version found
        }

        data.versionStr = version.substr(start, pos - start);

        // Remove trailing '.' if present
        if (!data.versionStr.empty() && data.versionStr.back() == '.')
        {
            data.versionStr.pop_back();
        }

        // Helper function to skip separators
        auto skipSeparators = [&]()
        {
            while (pos < version.size() && (version[pos] == '.' || version[pos] == '-' || version[pos] == '_'))
            {
                ++pos;
            }
        };

        skipSeparators();

        // Parse pre-release
        static constexpr std::array<const char*, 8> preIdentifiers = {
            "preview", "pre", "rc", "alpha", "beta", "c", "b", "a"};
        for (const char* id : preIdentifiers)
        {
            size_t idLen = std::strlen(id);
            if (version.compare(pos, idLen, id) == 0)
            {
                data.hasPreRelease = true;
                data.preReleaseStr = id;
                pos += idLen;

                // Normalize pre-release type
                if (data.preReleaseStr == "alpha")
                {
                    data.preReleaseStr = "a";
                }
                else if (data.preReleaseStr == "beta")
                {
                    data.preReleaseStr = "b";
                }
                else if (data.preReleaseStr == "c" || data.preReleaseStr == "pre" || data.preReleaseStr == "preview")
                {
                    data.preReleaseStr = "rc";
                }

                skipSeparators();

                // Parse pre-release number safely
                start = pos;
                while (pos < version.size() && std::isdigit(version[pos]))
                {
                    ++pos;
                }
                if (start != pos)
                {
                    data.preReleaseNumber = std::stoul(version.substr(start, pos - start));
                }
                else
                {
                    data.preReleaseNumber = 0;
                }
                break;
            }
        }

        skipSeparators();

        // Parse post-release
        static constexpr std::array<const char*, 3> postIdentifiers = {"post", "rev", "r"};
        for (const char* id : postIdentifiers)
        {
            size_t idLen = std::strlen(id);
            if (version.compare(pos, idLen, id) == 0)
            {
                data.hasPostRelease = true;
                pos += idLen;

                skipSeparators();

                // Parse post-release number safely
                start = pos;
                while (pos < version.size() && std::isdigit(version[pos]))
                {
                    ++pos;
                }
                if (start != pos)
                {
                    data.postReleaseNumber = std::stoul(version.substr(start, pos - start));
                }
                else
                {
                    data.postReleaseNumber = 0;
                }
                break;
            }
        }

        skipSeparators();

        // Parse dev-release
        if (version.compare(pos, 3, "dev") == 0)
        {
            data.hasDevRelease = true;
            pos += 3;

            skipSeparators();

            // Parse dev-release number safely
            start = pos;
            while (pos < version.size() && std::isdigit(version[pos]))
            {
                ++pos;
            }
            if (start != pos)
            {
                data.devReleaseNumber = std::stoul(version.substr(start, pos - start));
            }
            else
            {
                data.devReleaseNumber = 0;
            }
        }

        return !data.versionStr.empty(); // Successfully parsed
    }

    /**
     * @brief Constructor.
     *
     * @param version version PEP440 struct.
     */
    explicit VersionObjectPEP440(const PEP440& version)
        : m_epoch(version.epoch)
        , m_versionStr(version.versionStr)
        , m_preReleaseStr(version.preReleaseStr)
        , m_preReleaseNumber(version.preReleaseNumber)
        , m_postReleaseNumber(version.postReleaseNumber)
        , m_devReleaseNumber(version.devReleaseNumber)
        , m_hasPreRelease(version.hasPreRelease)
        , m_hasPostRelease(version.hasPostRelease)
        , m_hasDevRelease(version.hasDevRelease)
    {
    }
    // LCOV_EXCL_START
    ~VersionObjectPEP440() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Returns the VersionObjectType of this class.
     *
     * @return VersionObjectType.
     */
    VersionObjectType getType() override { return VersionObjectType::PEP440; }

    /**
     * @brief Comparison operator ==.
     *
     * @param b comparison rhs object.
     * @return true/false according to equality condition.
     */
    bool operator==(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectPEP440*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }
        return (m_epoch == pB->m_epoch && !compareVersionStr(m_versionStr, pB->m_versionStr)
                && m_preReleaseStr == pB->m_preReleaseStr && m_preReleaseNumber == pB->m_preReleaseNumber
                && m_postReleaseNumber == pB->m_postReleaseNumber && m_devReleaseNumber == pB->m_devReleaseNumber
                && m_hasPreRelease == pB->m_hasPreRelease && m_hasPostRelease == pB->m_hasPostRelease
                && m_hasDevRelease == pB->m_hasDevRelease);
    }

    /**
     * @brief Comparison operator <.
     *
     * @param b comparison rhs object.
     * @return true/false according to less than condition.
     */
    bool operator<(const IVersionObject& b) const override
    {
        const auto* pB = dynamic_cast<const VersionObjectPEP440*>(&b);
        if (pB == nullptr)
        {
            throw std::runtime_error {"Error casting VersionObject type"};
        }

        if (m_epoch < pB->m_epoch)
        {
            return true;
        }
        else if (m_epoch > pB->m_epoch)
        {
            return false;
        }

        int resultVersionStr = compareVersionStr(m_versionStr, pB->m_versionStr);
        if (resultVersionStr < 0)
        {
            return true;
        }
        else if (resultVersionStr > 0)
        {
            return false;
        }

        if (m_hasPreRelease && pB->m_hasPreRelease == false)
        {
            return true;
        }
        else if (m_hasPreRelease == false && pB->m_hasPreRelease)
        {
            return false;
        }
        else if (m_hasPreRelease && pB->m_hasPreRelease)
        {
            int resultPreReleaseStr = m_preReleaseStr.compare(pB->m_preReleaseStr);
            if (resultPreReleaseStr < 0)
            {
                return true;
            }
            else if (resultPreReleaseStr > 0)
            {
                return false;
            }

            if (m_preReleaseNumber < pB->m_preReleaseNumber)
            {
                return true;
            }
            else if (m_preReleaseNumber > pB->m_preReleaseNumber)
            {
                return false;
            }
        }

        if (m_hasPostRelease && pB->m_hasPostRelease == false)
        {
            return false;
        }
        else if (m_hasPostRelease == false && pB->m_hasPostRelease)
        {
            return true;
        }
        else if (m_hasPostRelease && pB->m_hasPostRelease)
        {
            if (m_postReleaseNumber < pB->m_postReleaseNumber)
            {
                return true;
            }
            else if (m_postReleaseNumber > pB->m_postReleaseNumber)
            {
                return false;
            }
        }

        if (m_hasDevRelease && pB->m_hasDevRelease == false)
        {
            return false;
        }
        else if (m_hasDevRelease == false && pB->m_hasDevRelease)
        {
            return true;
        }
        else if (m_hasDevRelease && pB->m_hasDevRelease)
        {
            if (m_devReleaseNumber < pB->m_devReleaseNumber)
            {
                return true;
            }
            else if (m_devReleaseNumber > pB->m_devReleaseNumber)
            {
                return false;
            }
        }

        return false;
    }
};

#endif // _VERSION_OBJECT_PEP440_HPP
