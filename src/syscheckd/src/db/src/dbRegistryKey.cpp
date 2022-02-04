/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
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
    fim_entry* fim = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));;
    fim_registry_key* key = reinterpret_cast<fim_registry_key*>(std::calloc(1, sizeof(fim_registry_key)));
    auto uid_size = std::to_string(m_uid).size();
    auto gid_size = std::to_string(m_gid).size();

    fim->type = FIM_TYPE_REGISTRY;
    key->arch = m_arch;
    std::strncpy(key->checksum, m_checksum.c_str(), sizeof(key->checksum));
    key->gid = static_cast<char*>(std::calloc(gid_size + 1, sizeof(char)));
    std::strncpy(key->gid, std::to_string(m_gid).c_str(), gid_size);
    key->group_name = const_cast<char*>(m_groupname.c_str());
    key->last_event = m_lastEvent;
    key->mtime = m_time;
    key->path = const_cast<char*>(m_identifier.c_str());
    key->perm = const_cast<char*>(m_perm.c_str());
    key->scanned =  m_scanned;
    key->uid = static_cast<char*>(std::calloc(uid_size + 1, sizeof(char)));
    std::strncpy(key->uid, std::to_string(m_uid).c_str(), uid_size);
    key->user_name = const_cast<char*>(m_username.c_str());
    fim->registry_entry.key = key;

    m_fimEntry = std::unique_ptr<fim_entry, FimRegistryKeyDeleter>(fim);
}

void RegistryKey::createJSON()
{
    nlohmann::json conf;
    nlohmann::json data;


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
    conf["data"] = nlohmann::json::array({data});

    if (m_oldData)
    {
        conf["return_old_data"] = true;
    }

    m_statementConf = std::make_unique<nlohmann::json>(conf);

}
