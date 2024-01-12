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
            key->arch = m_arch;
            std::snprintf(key->checksum, sizeof(key->checksum), "%s", m_checksum.c_str());
            key->gid = const_cast<char*>(m_gid.c_str());
            key->uid = const_cast<char*>(m_uid.c_str());
            key->group_name = const_cast<char*>(m_groupname.c_str());
            key->last_event = m_lastEvent;
            key->mtime = m_time;
            key->path = const_cast<char*>(m_identifier.c_str());
            key->hash_full_path = const_cast<char*>(m_hashpath.c_str());
            key->perm = const_cast<char*>(m_perm.c_str());
            key->scanned =  m_scanned;
            key->user_name = const_cast<char*>(m_username.c_str());

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
    data["arch"] = ((m_arch == 0) ? "[x32]" : "[x64]");
    data["last_event"] = m_lastEvent;
    data["scanned"] = m_scanned;
    data["checksum"] = m_checksum;
    data["perm"] = m_perm;
    data["uid"] = m_uid;
    data["gid"] = m_gid;
    data["user_name"] = m_username;
    data["group_name"] = m_groupname;
    data["mtime"] = m_time;
    data["hash_full_path"] = m_hashpath;

    conf["data"] = nlohmann::json::array({data});

    if (m_oldData)
    {
        options["return_old_data"] = true;
        options["ignore"] = nlohmann::json::array({"last_event"});
        conf["options"] = options;
    }

    m_statementConf = std::make_unique<nlohmann::json>(conf);

}
