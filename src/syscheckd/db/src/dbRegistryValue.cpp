/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 18, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "dbRegistryValue.hpp"

void RegistryValue::createFimEntry()
{
    fim_entry* fim = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));;
    fim_registry_value_data* value = reinterpret_cast<fim_registry_value_data*>(std::calloc(1, sizeof(fim_registry_value_data)));

    fim->type = FIM_TYPE_REGISTRY;
    value->size = m_size;
    value->id = m_keyUid;
    value->name = const_cast<char*>(m_identifier.c_str());
    std::strncpy(value->hash_md5, m_md5.c_str(), sizeof(value->hash_md5));
    std::strncpy(value->hash_sha1, m_sha1.c_str(), sizeof(value->hash_sha1));
    std::strncpy(value->hash_sha256, m_sha256.c_str(), sizeof(value->hash_sha256));
    value->mode = m_mode;
    value->last_event = m_lastEvent;
    value->scanned = m_scanned;
    std::strncpy(value->checksum, m_checksum.c_str(), sizeof(value->checksum));
    fim->registry_entry.value = value;
    m_fimEntry = std::unique_ptr<fim_entry, FimRegistryValueDeleter>(fim);
}

void RegistryValue::createJSON()
{
    nlohmann::json conf = {};

    conf.push_back(nlohmann::json::object_t::value_type("id", m_keyUid));
    conf.push_back(nlohmann::json::object_t::value_type("mode", m_mode));
    conf.push_back(nlohmann::json::object_t::value_type("last_event", m_lastEvent));
    conf.push_back(nlohmann::json::object_t::value_type("scanned", m_scanned));
    conf.push_back(nlohmann::json::object_t::value_type("name", m_identifier));
    conf.push_back(nlohmann::json::object_t::value_type("checksum", m_checksum));
    conf.push_back(nlohmann::json::object_t::value_type("size", m_size));
    conf.push_back(nlohmann::json::object_t::value_type("hash_md5", m_md5));
    conf.push_back(nlohmann::json::object_t::value_type("hash_sha1", m_sha1));
    conf.push_back(nlohmann::json::object_t::value_type("hash_sha256", m_sha256));
    conf.push_back(nlohmann::json::object_t::value_type("type", m_type));
    m_statementConf = std::make_unique<nlohmann::json>(conf);
}
