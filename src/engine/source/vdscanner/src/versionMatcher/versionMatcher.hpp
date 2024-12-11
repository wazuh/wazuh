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

#ifndef _VERSION_MATCHER_HPP
#define _VERSION_MATCHER_HPP

#include "iVersionObjectInterface.hpp"
#include "versionObjectCalVer.hpp"
#include "versionObjectDpkg.hpp"
#include "versionObjectMajorMinor.hpp"
#include "versionObjectPEP440.hpp"
#include "versionObjectRpm.hpp"
#include "versionObjectSemVer.hpp"
#include <memory>
#include <stdexcept>
#include <string>
#include <variant>

enum class VersionComparisonResult : int
{
    A_LESS_THAN_B,
    A_EQUAL_B,
    A_GREATER_THAN_B
};

enum class VersionMatcherStrategy : int
{
    Unspecified = 0,
    Windows = 1,
    MacOS = 2,
    Pacman = 3,
    Snap = 4,
    PKG = 5,
    APK = 6
};

using PackageMap = std::unordered_map<std::string_view, std::variant<VersionObjectType, VersionMatcherStrategy>>;

/**
 * @brief VersionMatcher class.
 *
 */
class VersionMatcher final
{
private:
    /**
     * @brief Creates the corresponding version object using a strategy (VersionMatcherStrategy).
     *
     * @note A strategy is a set of rules to match a version string to a version object. For example, the default
     * strategy is to try to match the version string to a CalVer object, if it doesn't match, then it tries to match it
     * to a PEP440 object, and so on. If the version string doesn't match any of the specified types, it will return a
     * nullptr.
     *
     *
     * @param version string version item to create object from
     * @param strategy VersionMatcherStrategy to use.
     * @return std::shared_ptr<IVersionObject>
     */
    static std::shared_ptr<IVersionObject> createVersionObject(const std::string& version,
                                                               const VersionMatcherStrategy& strategy)
    {
        std::shared_ptr<IVersionObject> matcher;

        switch (strategy)
        {
            case VersionMatcherStrategy::Windows:
            case VersionMatcherStrategy::MacOS:
            case VersionMatcherStrategy::PKG:
            case VersionMatcherStrategy::Pacman:
            case VersionMatcherStrategy::Snap: return createVersionObject(version, VersionObjectType::DPKG); break;
            case VersionMatcherStrategy::APK:
                // TODO: Define the APK strategy
            case VersionMatcherStrategy::Unspecified:
                if (matcher = createVersionObject(version, VersionObjectType::CalVer); matcher)
                {
                    return matcher;
                }
                else if (matcher = createVersionObject(version, VersionObjectType::PEP440); matcher)
                {
                    return matcher;
                }
                else if (matcher = createVersionObject(version, VersionObjectType::MajorMinor); matcher)
                {
                    return matcher;
                }
                else if (matcher = createVersionObject(version, VersionObjectType::SemVer); matcher)
                {
                    return matcher;
                }
                else if (matcher = createVersionObject(version, VersionObjectType::DPKG); matcher)
                {
                    return matcher;
                }
                else if (matcher = createVersionObject(version, VersionObjectType::RPM); matcher)
                {
                    return matcher;
                }
                else
                {
                    // LCOV_EXCL_STARTi
                    LOG_DEBUG("Error creating VersionObject (Unspecified). Version string doesn't match "
                              "any of the specified types. Version string: {}",
                              version);
                    // LCOV_EXCL_STOP
                }
                break;
                // LCOV_EXCL_START
            default:
                LOG_DEBUG("Error creating VersionObject: Invalid strategy.");
                break;
                // LCOV_EXCL_STOP
        }

        return nullptr;
    } // LCOV_EXCL_LINE

    /**
     * @brief Creates a VersionObject from a specific VersionObjectType.
     *
     * @param version string version item to create object from
     * @param type VersionObjectType to use (CalVer, PEP440, MajorMinor, SemVer, DPKG, RPM, etc).
     *
     * @note If the version string doesn't match the specified type it will return nullptr.
     *
     * @return std::shared_ptr<IVersionObject>
     */
    static std::shared_ptr<IVersionObject> createVersionObject(const std::string& version,
                                                               const VersionObjectType& type)
    {
        CalVer calVer {};
        PEP440 pep440 {};
        MajorMinor majorMinor {};
        SemVer semVer {};
        Dpkg dpkgVer {};
        Rpm rpmVer {};

        switch (type)
        {
            case VersionObjectType::CalVer:
                if (VersionObjectCalVer::match(version, calVer))
                {
                    return std::make_shared<VersionObjectCalVer>(calVer);
                }
                LOG_DEBUG("Error creating VersionObject (CalVer). Version string doesn't match the specified type. "
                          "Version string: {}",
                          version);
                break;

            case VersionObjectType::PEP440:
                if (VersionObjectPEP440::match(version, pep440))
                {
                    return std::make_shared<VersionObjectPEP440>(pep440);
                }
                LOG_DEBUG("Error creating VersionObject (PEP440). Version string doesn't match the specified type. "
                          "Version string: {}",
                          version);
                break;

            case VersionObjectType::MajorMinor:
                if (VersionObjectMajorMinor::match(version, majorMinor))
                {
                    return std::make_shared<VersionObjectMajorMinor>(majorMinor);
                }
                LOG_DEBUG("Error creating VersionObject (MajorMinor). Version string doesn't match the specified type. "
                          "Version string: {}",
                          version);
                break;

            case VersionObjectType::SemVer:
                if (VersionObjectSemVer::match(version, semVer))
                {
                    return std::make_shared<VersionObjectSemVer>(semVer);
                }
                LOG_DEBUG("Error creating VersionObject (SemVer). Version string doesn't match the specified type. "
                          "Version string: {}",
                          version);
                break;

            case VersionObjectType::DPKG:
                if (VersionObjectDpkg::match(version, dpkgVer))
                {
                    return std::make_shared<VersionObjectDpkg>(dpkgVer);
                }
                LOG_DEBUG("Error creating VersionObject (DPKG). Version string doesn't match the specified type. "
                          "Version string: {}",
                          version);
                break;

            case VersionObjectType::RPM:
                if (VersionObjectRpm::match(version, rpmVer))
                {
                    return std::make_shared<VersionObjectRpm>(rpmVer);
                }
                LOG_DEBUG("Error creating VersionObject (RPM). Version string doesn't match the specified type. "
                          "Version string: {}",
                          version);
                break;

            default:
                // LCOV_EXCL_START
                LOG_DEBUG("Error creating VersionObject: Invalid type.");
                break;
                // LCOV_EXCL_STOP
        }
        return nullptr;
    } // LCOV_EXCL_LINE

    /**
     * @brief Creates a version object using the string and type specified.
     *
     * @param version string version item to create object from
     * @param type Version object or matcher strategy.
     *
     * @return std::shared_ptr<IVersionObject>
     */
    static std::shared_ptr<IVersionObject>
    createVersionObject(const std::string& version, std::variant<VersionObjectType, VersionMatcherStrategy> type)
    {
        if (std::holds_alternative<VersionObjectType>(type))
        {
            return createVersionObject(version, std::get<VersionObjectType>(type));
        }
        else if (std::holds_alternative<VersionMatcherStrategy>(type))
        {
            return createVersionObject(version, std::get<VersionMatcherStrategy>(type));
        }
        else
        {
            // LCOV_EXCL_START

            LOG_DEBUG("Error creating VersionObject: Invalid type.");
            return nullptr;
            // LCOV_EXCL_STOP
        }
    }

public:
    /**
     * @brief Compares 2 version strings.
     *
     * @param versionA string version item A to compare
     * @param versionB string version item B to compare
     * @param type Version object or matcher strategy to compare A and B.
     * @return VersionComparisonResult result of the comparison.
     */
    static VersionComparisonResult
    compare(const std::string& versionA,
            const std::string& versionB,
            std::variant<VersionObjectType, VersionMatcherStrategy> type = VersionMatcherStrategy::Unspecified)
    {
        auto pVersionObjectA = createVersionObject(versionA, type);
        auto pVersionObjectB = createVersionObject(versionB, type);

        if (pVersionObjectA && pVersionObjectB && pVersionObjectA->getType() == pVersionObjectB->getType())
        {

            if (*pVersionObjectA == *pVersionObjectB)
            {
                return VersionComparisonResult::A_EQUAL_B;
            }
            else if (*pVersionObjectA < *pVersionObjectB)
            {
                return VersionComparisonResult::A_LESS_THAN_B;
            }
            else
            {
                return VersionComparisonResult::A_GREATER_THAN_B;
            }
        }

        throw std::invalid_argument("Unable to compare versions (" + versionA + " vs " + versionB + ").");
    }

    /**
     * @brief Checks whether a version string matches the given version type.
     *
     * @details An unspecified version type is not allowed.
     *
     * @param version Version to validate.
     * @param type Version object or matcher strategy.
     * @return true If the version is valid.
     * @return false If the version is not valid.
     */
    static bool match(const std::string& version, std::variant<VersionObjectType, VersionMatcherStrategy> type)
    {
        return (nullptr != createVersionObject(version, type));
    }
};

#endif // _VERSION_MATCHER_HPP
