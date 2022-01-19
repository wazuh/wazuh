/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * April 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "sharedDefs.h"
#include <alpm.h>
#include <package.h>
#include "packageLinuxParserHelperExtra.h"


struct AlmpDeleter final
{
    void operator()(alpm_handle_t* pArchHandle)
    {
        alpm_release(pArchHandle);
    }
};

void getPacmanInfo(const std::string& libPath, std::function<void(nlohmann::json&)> callback)
{
    constexpr auto ROOT_PATH {"/"};
    alpm_errno_t err {ALPM_ERR_OK};
    auto pArchHandle {alpm_initialize(ROOT_PATH, libPath.c_str(), &err)};

    if (!pArchHandle)
    {
        throw std::runtime_error
        {
            std::string{"alpm_initialize failure: "} + alpm_strerror(err)
        };
    }

    const std::unique_ptr<alpm_handle_t, AlmpDeleter> spDbHandle{pArchHandle};
    auto pDbLocal {alpm_get_localdb(spDbHandle.get())};

    if (!pDbLocal)
    {
        throw std::runtime_error
        {
            std::string{"alpm_get_localdb failure: "} + alpm_strerror(alpm_errno(spDbHandle.get()))
        };
    }

    for (auto pArchItem{alpm_db_get_pkgcache(pDbLocal)}; pArchItem; pArchItem = alpm_list_next(pArchItem))
    {
        auto packageInfo = PackageLinuxHelper::parsePacman(pArchItem);

        if (!packageInfo.empty())
        {
            callback(packageInfo);
        }
    }
}
