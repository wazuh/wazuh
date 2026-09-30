/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * December 14, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _PACKAGE_INTERFACE_WRAPPER_H
#define _PACKAGE_INTERFACE_WRAPPER_H
#include "ipackageInterface.h"
#include <optional>

class IPackageWrapper
{
    public:
        // LCOV_EXCL_START
        virtual ~IPackageWrapper() = default;
        // LCOV_EXCL_STOP
        virtual std::string name() const = 0;
        virtual std::string version() const = 0;
        virtual std::string groups() const = 0;
        virtual std::string description() const = 0;
        virtual std::string architecture() const = 0;
        virtual std::string format() const = 0;
        virtual std::string osPatch() const = 0;
        virtual std::string source() const = 0;
        virtual std::string location() const = 0;
        virtual std::string priority() const = 0;
        /// @return The installed size in bytes, or no value when it could not be established.
        /// An empty result means "unknown", never zero: the caller leaves the field out of the
        /// package document so the stored value is kept rather than overwritten by a failed
        /// measurement, which would otherwise churn the package's checksum.
        virtual std::optional<int64_t> size() const = 0;
        virtual std::string vendor() const = 0;
        virtual std::string install_time() const = 0;
        virtual std::string multiarch() const = 0;
};
#endif // _PACKAGE_INTERFACE_WRAPPER_H
