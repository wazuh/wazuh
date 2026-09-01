/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
 * December 22, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "packageLinuxDataRetriever.h"
#include "iberkeleyDbWrapper.h"
#include "berkeleyRpmDbHelper.h"
#include "sharedDefs.h"
#include "packageLinuxRpmParserHelper.h"
#include "packageLinuxRpmParserHelperLegacy.h"
#include "rpmDbNdbReader.hpp"
#include "rpmDbSqliteReader.hpp"
#include "rpmHeaderBlobParser.hpp"
#include "stringHelper.h"
#include "rpmlib.h"

#include <filesystem_wrapper.hpp>

void getRpmInfo(std::function<void(nlohmann::json&)> callback)
{

    const auto rpmDefaultQuery
    {
        [](std::function<void(nlohmann::json&)> cb)
        {
            const auto rawRpmPackagesInfo{ UtilsWrapperLinux::exec("rpm -qa --qf '%{name}\t%{arch}\t%{summary}\t%{size}\t%{epoch}\t%{release}\t%{version}\t%{vendor}\t%{installtime}\t%{group}\t\n'") };

            if (!rawRpmPackagesInfo.empty())
            {
                const auto rows { Utils::split(rawRpmPackagesInfo, '\n') };

                for (const auto& row : rows)
                {
                    auto package = PackageLinuxHelper::parseRpm(row);

                    if (!package.empty())
                    {
                        cb(package);
                    }
                }
            }
        }
    };

    if (!UtilsWrapperLinux::existsRegular(RPM_DATABASE))
    {
        // We are probably using RPM >= 4.16 – get the packages from librpm.
        try
        {
            RpmPackageManager rpm{std::make_shared<RpmLib>()};

            for (const auto& p : rpm)
            {
                auto packageJson = PackageLinuxHelper::parseRpm(p);

                if (!packageJson.empty())
                {
                    callback(packageJson);
                }
            }
        }
        catch (...)
        {
            rpmDefaultQuery(callback);
        }
    }
    else
    {
        try
        {
            BerkeleyRpmDBReader db {std::make_shared<BerkeleyDbWrapper>(RPM_DATABASE)};
            auto row = db.getNext();

            // Get the packages from the Berkeley DB.
            while (!row.empty())
            {
                auto package = PackageLinuxHelper::parseRpm(row);

                if (!package.empty())
                {
                    callback(package);
                }

                row = db.getNext();
            }
        }
        catch (...)
        {
            rpmDefaultQuery(callback);
        }
    }
}

bool getRpmInfoFromLocation(const std::string& dbPath, std::function<void(nlohmann::json&)> callback)
{
    // The database file names rpm uses for each of the two formats read here. Berkeley DB
    // is deliberately absent: it is the format the host path above already covers, and
    // reading it needs libdb pointed at a whole directory.
    const auto SQLITE_DATABASE { "rpmdb.sqlite" };
    const auto NDB_DATABASE { "Packages.db" };

    const auto directory { dbPath.empty() || dbPath.back() == '/' ? dbPath : dbPath + "/" };

    const auto emit
    {
        [&callback](const uint8_t* blob, std::size_t size)
        {
            const auto header { RpmHeaderBlob::parse(blob, size) };

            if (header.valid)
            {
                auto package { PackageLinuxHelper::parseRpm(RpmHeaderBlob::toRow(header)) };

                if (!package.empty())
                {
                    callback(package);
                }
            }
        }
    };

    return RpmDbSqlite::readFromLocation(directory + SQLITE_DATABASE, emit) ||
           RpmDbNdb::readFromLocation(directory + NDB_DATABASE, emit);
}

void getRpmPythonPackages(std::unordered_set<std::string>& pythonPackages)
{
    std::vector<std::string> pythonFiles;

    const auto rpmPythonDefaultQuery
    {
        [](std::vector<std::string>& pFiles)
        {
            const auto rawPythonPackagesList
            {
                UtilsWrapperLinux::exec(
                    "rpm -qa | grep -E 'python.*' | xargs -I {} rpm -ql {} | grep -E '\\.egg-info$|\\.dist-info$'")};

            if (!rawPythonPackagesList.empty())
            {
                const auto rows {Utils::split(rawPythonPackagesList, '\n')};

                for (const auto& row : rows)
                {
                    pFiles.push_back(row);
                }
            }
        }
    };

    const auto filterPythonFiles
    {
        [&pythonPackages](const std::vector<std::string>& pFiles)
        {
            const auto PYTHON_INFO_FILES = std::array
            {
                std::make_pair(std::regex(R"(^.*\.egg-info$)"), "/PKG-INFO"),
                std::make_pair(std::regex(R"(^.*\.dist-info$)"), "/METADATA")};

            for (const auto& file : pFiles)
            {
                std::smatch match;
                const file_system::FileSystemWrapper fileSystemWrapper;

                for (const auto& [pattern, extraFile] : PYTHON_INFO_FILES)
                {
                    if (std::regex_search(file, match, pattern))
                    {
                        std::string baseInfoPath = match.str(0);

                        if (fileSystemWrapper.is_regular_file(baseInfoPath))
                        {
                            pythonPackages.insert(std::move(baseInfoPath));
                        }
                        else
                        {
                            std::string fullPath = baseInfoPath + extraFile;

                            if (fileSystemWrapper.exists(fullPath))
                            {
                                pythonPackages.insert(std::move(fullPath));
                            }
                        }
                    }
                }
            }
        }
    };

    if (!UtilsWrapperLinux::existsRegular(RPM_DATABASE))
    {
        // We are probably using RPM >= 4.16 – get Python package files from librpm.
        try
        {
            RpmPackageManager rpm {std::make_shared<RpmLib>()};

            for (const auto& p : rpm)
            {
                if (!p.files.empty())
                {
                    for (const auto& file : p.files)
                    {
                        pythonFiles.push_back(file);
                    }
                }
            }
        }
        catch (...)
        {
            rpmPythonDefaultQuery(pythonFiles);
        }
    }
    else
    {
        try
        {
            BerkeleyRpmDBReader db {std::make_shared<BerkeleyDbWrapper>(RPM_DATABASE)};

            // Get Python package files from the Berkeley DB.
            while (db.getNextPythonFiles(pythonFiles));
        }
        catch (...)
        {
            rpmPythonDefaultQuery(pythonFiles);
        }
    }

    if (!pythonFiles.empty())
    {
        filterPythonFiles(pythonFiles);
    }
}
