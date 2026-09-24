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

#include "packageMac.h"
#include "sharedDefs.h"
#include "brewWrapper.h"
#include "pkgWrapper.h"
#include "macportsWrapper.h"
#include "timeHelper.h"
#include "stringHelper.h"
#include "packages/packageFamilyDataAFactory.h"
#include <filesystem>
#include <filesystem_wrapper.hpp>
#include <iostream>

namespace
{
    const std::string MACPORTS_DB_NAME {"registry.db"};
    // The registry holds no size column, and `location` points at the compressed archive the port
    // was built into rather than at installed content, so the installed paths are gathered here and
    // summed by the wrapper. char(1) separates them because a path may legally contain a newline.
    const std::string MACPORTS_QUERY
    {
        "SELECT p.name, p.version, p.date, p.location, p.archs, "
        "(SELECT group_concat(f.actual_path, char(1)) FROM files f WHERE f.id = p.id AND f.active = 1) "
        "FROM ports p WHERE p.state = 'installed';"
    };
}

std::shared_ptr<IPackage> FactoryBSDPackage::create(const std::pair<PackageContext, int>& ctx)
{
    std::shared_ptr<IPackage> ret;

    if (ctx.second == BREW)
    {
        ret = std::make_shared<BSDPackageImpl>(std::make_shared<BrewWrapper>(ctx.first));
    }
    else if (ctx.second == PKG || ctx.second == RCP)
    {
        ret = std::make_shared<BSDPackageImpl>(std::make_shared<PKGWrapper>(ctx.first));
    }
    else
    {
        throw std::runtime_error { "Error creating BSD package data retriever." };
    }

    return ret;
}

std::shared_ptr<IPackage> FactoryBSDPackage::create(const std::pair<SQLite::IStatement&, const int>& ctx)
{
    std::shared_ptr<IPackage> ret;

    if (ctx.second == MACPORTS)
    {
        ret = std::make_shared<BSDPackageImpl>(std::make_shared<MacportsWrapper>(ctx.first));
    }
    else
    {
        throw std::runtime_error { "Error creating BSD package data retriever." };
    }

    return ret;
}

BSDPackageImpl::BSDPackageImpl(const std::shared_ptr<IPackageWrapper>& packageWrapper)
    : m_packageWrapper(packageWrapper)
{ }

void BSDPackageImpl::buildPackageData(nlohmann::json& package)
{
    package["name"] = m_packageWrapper->name();
    package["version_"] = m_packageWrapper->version();
    package["category"] = m_packageWrapper->groups();
    package["description"] = m_packageWrapper->description();
    package["architecture"] = m_packageWrapper->architecture();
    package["type"] = m_packageWrapper->format();
    package["source"] = m_packageWrapper->source();
    package["path"] = m_packageWrapper->location();
    package["priority"] = m_packageWrapper->priority();
    package["size"] = m_packageWrapper->size();
    package["vendor"] = m_packageWrapper->vendor();
    auto installed = Utils::timestampToISO8601(m_packageWrapper->install_time());
    package["installed"] = installed.empty() ? UNKNOWN_VALUE : installed;
    package["multiarch"] = m_packageWrapper->multiarch();
}

void getPackagesFromPath(const std::string& pkgDirectory, const int pkgType, std::function<void(nlohmann::json&)> callback, bool rejectSymlinks)
{
    const file_system::FileSystemWrapper fs;

    if (MACPORTS == pkgType)
    {
        if (fs.is_regular_file(pkgDirectory + "/" + MACPORTS_DB_NAME))
        {
            try
            {
                std::shared_ptr<SQLite::IConnection> sqliteConnection = std::make_shared<SQLite::Connection>(pkgDirectory + "/" + MACPORTS_DB_NAME);

                SQLite::Statement stmt
                {
                    sqliteConnection,
                    MACPORTS_QUERY
                };

                std::pair<SQLite::IStatement&, const int&> pkgContext {std::make_pair(std::ref(stmt), std::cref(pkgType))};

                while (SQLITE_ROW == stmt.step())
                {
                    try
                    {
                        nlohmann::json jsPackage;
                        FactoryPackageFamilyCreator<OSPlatformType::BSDBASED>::create(pkgContext)->buildPackageData(jsPackage);

                        if (!jsPackage.at("name").get_ref<const std::string&>().empty())
                        {
                            // Only return valid content packages
                            callback(jsPackage);
                        }
                    }
                    catch (const std::exception& e)
                    {
                        std::cerr << e.what() << std::endl;
                    }
                }
            }
            catch (const std::exception& e)
            {
                std::cerr << e.what() << std::endl;
            }
        }
    }
    else
    {
        const auto packages { fs.list_directory(pkgDirectory) };

        // Shared by every branch below: build one package's data and hand it to the caller,
        // discarding anything with an empty name and logging (not propagating) any failure
        // so one bad entry never aborts the rest of the scan.
        const auto buildAndReportPackage
        {
            [&callback, pkgType](const std::string & filePath, const std::string & packageName, const std::string& version = "")
            {
                try
                {
                    nlohmann::json jsPackage;
                    FactoryPackageFamilyCreator<OSPlatformType::BSDBASED>::create(std::make_pair(PackageContext{filePath, packageName, version}, pkgType))->buildPackageData(jsPackage);

                    if (!jsPackage.at("name").get_ref<const std::string&>().empty())
                    {
                        // Only return valid content packages
                        callback(jsPackage);
                    }
                }
                catch (const std::exception& e)
                {
                    std::cerr << e.what() << std::endl;
                }
            }
        };

        // Only meaningful when rejectSymlinks is true, for a caller scanning a user-writable
        // root: there, a symlink can point anywhere else that user does not own, another
        // user's own Applications folder (so their apps get attributed to whoever placed the
        // link), the very directory this scan already covers (so the same install is reported
        // twice, doubling vulnerability alerts for it), or a bundle only root can read (so this
        // root-run scan reads it on the placer's behalf). Reject it outright instead of
        // resolving it. A status this can't read is treated the same as a symlink: safer to
        // skip the entry than to risk following it.
        //
        // Fixed, root-owned locations (/Applications and the rest of s_mapPackagesDirectories)
        // must NOT reject symlinks: Apple itself ships /Applications/Safari.app as a symlink
        // into /System/Cryptexes/App since macOS 13, and third-party tooling (nix-darwin,
        // home-manager, an app kept on an external volume) links into /Applications the same
        // way. Rejecting those there would silently drop real, already-installed software from
        // the inventory, which is the opposite of this fix's intent.
        const auto isSymlinkOrUnknown
        {
            [&fs](const std::filesystem::path & entryPath)
            {
                try
                {
                    return fs.is_symlink(entryPath);
                }
                catch (const std::exception& e)
                {
                    std::cerr << e.what() << std::endl;
                    return true;
                }
            }
        };

        for (const auto& package : packages)
        {
            if (rejectSymlinks && isSymlinkOrUnknown(package))
            {
                continue;
            }

            if ((PKG == pkgType && Utils::endsWith(package, ".app")) ||
                    (RCP == pkgType && Utils::endsWith(package, ".plist")))
            {
                buildAndReportPackage(pkgDirectory, package.filename().string());
            }
            else if (BREW == pkgType)
            {
                if (fs.is_directory(package) && !Utils::startsWith(package.filename().string(), "."))

                {
                    const auto packageVersions { fs.list_directory(package) };

                    for (const auto& versionPath : packageVersions)
                    {
                        const std::string version = versionPath.filename().string();

                        if (!Utils::startsWith(version, "."))
                        {
                            buildAndReportPackage(pkgDirectory, package.filename().string(), version);
                        }
                    }
                }
            }
            else if (PKG == pkgType)
            {
                // Entries under a user-writable directory (e.g. a per-user ~/Applications) can be a
                // symlink loop or otherwise fail is_directory/list_directory with a filesystem_error.
                // Keep that isolated to this one entry instead of aborting the rest of the scan.
                bool isEligibleSubdirectory = false;

                try
                {
                    isEligibleSubdirectory = fs.is_directory(package) && !Utils::startsWith(package.filename().string(), ".");
                }
                catch (const std::exception& e)
                {
                    std::cerr << e.what() << std::endl;
                }

                if (isEligibleSubdirectory)
                {
                    try
                    {
                        // Vendors sometimes group their apps one level down (e.g. /Applications/<Vendor>/<App>.app).
                        // Look exactly one level below, no further, so nested helper bundles inside a .app are not walked into.
                        const auto nestedEntries { fs.list_directory(package) };

                        for (const auto& nestedEntry : nestedEntries)
                        {
                            if (Utils::endsWith(nestedEntry, ".app") && (!rejectSymlinks || !isSymlinkOrUnknown(nestedEntry)))
                            {
                                buildAndReportPackage(package.string(), nestedEntry.filename().string());
                            }
                        }
                    }
                    catch (const std::exception& e)
                    {
                        std::cerr << e.what() << std::endl;
                    }
                }
            }

            // else: invalid package
        }
    }
}
