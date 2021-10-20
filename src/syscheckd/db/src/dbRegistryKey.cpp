/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 15, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "dbRegistryKey.hpp"

void RegistryKey::createFimEntry()
{
    fim_entry* fim = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));;
    fim_registry_key* key = reinterpret_cast<fim_registry_key*>(std::calloc(1, sizeof(fim_registry_key)));

    fim->type = FIM_TYPE_REGISTRY;
    key->id = std::atoi(m_identifier.c_str());
    key->arch = m_arch;
    std::strncpy(key->checksum, m_checksum.c_str(), sizeof(key->checksum));
    key->gid = reinterpret_cast<char*>(std::calloc(1, sizeof(char*)));
    std::strncpy(key->gid, std::to_string(m_gid).c_str(), sizeof(std::to_string(m_gid).size()));
    key->group_name = const_cast<char*>(m_groupname.c_str());
    key->last_event = m_lastEvent;
    key->mtime = m_time;
    key->path = const_cast<char*>(m_path.c_str());
    key->perm = const_cast<char*>(m_perm.c_str());
    key->scanned =  m_scanned;
    key->uid = reinterpret_cast<char*>(std::calloc(1, sizeof(char*)));
    std::strncpy(key->uid, std::to_string(m_uid).c_str(), sizeof(std::to_string(m_uid).size()));
    key->user_name = const_cast<char*>(m_username.c_str());
    fim->registry_entry.key = key;

    m_fimEntry = std::unique_ptr<fim_entry, FimRegistryKeyDeleter>(fim);
}

void RegistryKey::createJSON()
{
    nlohmann::json conf = {};

    conf.push_back(nlohmann::json::object_t::value_type("arch", m_arch));
    conf.push_back(nlohmann::json::object_t::value_type("id", m_identifier));
    conf.push_back(nlohmann::json::object_t::value_type("last_event", m_lastEvent));
    conf.push_back(nlohmann::json::object_t::value_type("scanned", m_scanned));
    conf.push_back(nlohmann::json::object_t::value_type("checksum", m_checksum));
    conf.push_back(nlohmann::json::object_t::value_type("path", m_path));
    conf.push_back(nlohmann::json::object_t::value_type("perm", m_perm));
    conf.push_back(nlohmann::json::object_t::value_type("uid", m_uid));
    conf.push_back(nlohmann::json::object_t::value_type("gid", m_gid));
    conf.push_back(nlohmann::json::object_t::value_type("user_name", m_username));
    conf.push_back(nlohmann::json::object_t::value_type("group_name", m_groupname));
    conf.push_back(nlohmann::json::object_t::value_type("mtime", m_time));

    m_statementConf = std::make_unique<nlohmann::json>(conf);
}
