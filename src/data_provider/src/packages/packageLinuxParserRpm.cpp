/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
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
#include "packageLinuxParserHelper.h"
#include "filesystemHelper.h"
#include "rpmlib.h"

void getRpmInfo(std::function<void(nlohmann::json&)> callback)
{
    if (!Utils::existsRegular(RPM_DATABASE))
    {
        // We are probably using RPM >= 4.16 – get the packages from librpm.
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
    else
    {
        BerkeleyRpmDBReader db {std::make_shared<BerkeleyDbWrapper>(RPM_DATABASE)};
        auto row {db.getNext()};

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
}
