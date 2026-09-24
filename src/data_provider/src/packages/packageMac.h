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

#ifndef _PACKAGE_MAC_H
#define _PACKAGE_MAC_H

#include <functional>
#include "ipackageInterface.h"
#include "ipackageWrapper.h"
#include "sqliteWrapperTemp.h"

struct PackageContext
{
    std::string filePath;
    std::string package;
    std::string version;
};

class FactoryBSDPackage
{
    public:
        static std::shared_ptr<IPackage>create(const std::pair<PackageContext, int>& ctx);
        static std::shared_ptr<IPackage>create(const std::pair<SQLite::IStatement&, const int>& ctx);
};

class BSDPackageImpl final : public IPackage
{
        const std::shared_ptr<IPackageWrapper> m_packageWrapper;
    public:
        explicit BSDPackageImpl(const std::shared_ptr<IPackageWrapper>& packageWrapper);

        void buildPackageData(nlohmann::json& package) override;
};

// pkgType is one of the PKG/RCP/BREW/MACPORTS constants declared in sharedDefs.h.
// Exposed here (rather than kept file-local to sysInfoMac.cpp, where SysInfo::getPackages()
// calls it) so it can be exercised directly against a real temporary directory in tests,
// without dragging in the rest of sysInfoMac.cpp's unrelated hardware/network/users code.
//
// rejectSymlinks must be true only for a user-writable root (e.g. a per-user ~/Applications):
// there, a symlink can misattribute another user's installs, double-report an already-scanned
// directory, or hand this root-run scan a bundle only root can read. It must be false for
// fixed, root-owned locations such as /Applications, where Apple and third-party tooling
// legitimately ship real entries (e.g. /Applications/Safari.app) as symlinks.
void getPackagesFromPath(const std::string& pkgDirectory, const int pkgType, std::function<void(nlohmann::json&)> callback, bool rejectSymlinks);

#endif // _PACKAGE_MAC_H
