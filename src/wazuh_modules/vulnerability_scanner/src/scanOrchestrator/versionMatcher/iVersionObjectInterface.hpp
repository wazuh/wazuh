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

#ifndef _I_VERSION_OBJECT_INTERFACE_HPP
#define _I_VERSION_OBJECT_INTERFACE_HPP

enum class VersionObjectType : int
{
    CalVer = 0,
    PEP440 = 1,
    MajorMinor = 2,
    SemVer = 3,
    DPKG = 4,
    RPM = 5
};

/**
 * @brief IVersionObject class.
 *
 */
class IVersionObject
{
public:
    // LCOV_EXCL_START
    virtual ~IVersionObject() = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Returns the VersionObjectType of the concrete class.
     *
     * @return VersionObjectType.
     */
    virtual VersionObjectType getType() = 0;

    /**
     * @brief Comparison operator ==.
     *
     * @param b comparison rhs object.
     * @return true/false according to equality condition.
     */
    virtual bool operator==(const IVersionObject& b) const = 0;

    /**
     * @brief Comparison operator <.
     *
     * @param b comparison rhs object.
     * @return true/false according to less than condition.
     */
    virtual bool operator<(const IVersionObject& b) const = 0;
};

#endif // _I_VERSION_OBJECT_INTERFACE_HPP
