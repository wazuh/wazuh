/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * October 15, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbRegistryKey.hpp"
#include "fimCommonDefs.h"

void RegistryKey::createFimEntry()
{
    fim_entry* fim = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));
    fim_registry_key* key = reinterpret_cast<fim_registry_key*>(std::calloc(1, sizeof(fim_registry_key)));

    if (fim)
    {
        fim->type = FIM_TYPE_REGISTRY;

        if (key)
        {
            key->architecture = m_architecture;
            std::snprintf(key->checksum, sizeof(key->checksum), "%s", m_checksum.c_str());
            key->gid = const_cast<char*>(m_gid.c_str());
            key->uid = const_cast<char*>(m_uid.c_str());
            key->group = const_cast<char*>(m_group.c_str());
            key->mtime = m_time;
            key->path = const_cast<char*>(m_identifier.c_str());
            key->permissions = const_cast<char*>(m_permissions.c_str());
            key->owner = const_cast<char*>(m_owner.c_str());

            fim->registry_entry.key = key;
            m_fimEntry = std::unique_ptr<fim_entry, FimRegistryKeyDeleter>(fim);
        }
        // LCOV_EXCL_START
        else
        {
            throw std::runtime_error("The memory for fim_registry_key could not be allocated.");
        }

        // LCOV_EXCL_STOP
    }
    // LCOV_EXCL_START
    else
    {
        throw std::runtime_error("The memory for fim_entry could not be allocated.");
    }

    // LCOV_EXCL_STOP
}

void RegistryKey::createJSON()
{
    nlohmann::json conf;
    nlohmann::json data;
    nlohmann::json options;

    conf["table"] = FIMDB_REGISTRY_KEY_TABLENAME;
    data["path"] = m_identifier;
    data["architecture"] = ((m_architecture == 0) ? "[x32]" : "[x64]");
    data["checksum"] = m_checksum;
    data["permissions"] = m_permissions;
    data["uid"] = m_uid;
    data["gid"] = m_gid;
    data["owner"] = m_owner;
    data["group"] = m_group;
    data["mtime"] = m_time;

    conf["data"] = nlohmann::json::array({data});

    if (m_oldData)
    {
        options["return_old_data"] = true;
        options["ignore"] = nlohmann::json::array({"last_event"});
        conf["options"] = options;
    }

    m_statementConf = std::make_unique<nlohmann::json>(conf);

}
