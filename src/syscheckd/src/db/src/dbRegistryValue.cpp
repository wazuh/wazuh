/*
 * Wazuh Syscheck
 * Copyright (C) 2015-2021, Wazuh Inc.
 * October 18, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbRegistryValue.hpp"
#include "fimCommonDefs.h"

void RegistryValue::createFimEntry()
{
    fim_entry* fim = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));;
    fim_registry_value_data* value = reinterpret_cast<fim_registry_value_data*>(std::calloc(1, sizeof(fim_registry_value_data)));

    fim->type = FIM_TYPE_REGISTRY;
    value->path = const_cast<char*>(m_path.c_str());
    value->size = m_size;
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

    nlohmann::json conf;
    nlohmann::json data;

    conf["table"] = FIMDB_REGISTRY_VALUE_TABLENAME;
    data["path"] = m_path;
    data["arch"] = ((m_arch == 0) ? "[x32]" : "[x64]");
    data["name"] = m_identifier;
    data["last_event"] = m_lastEvent;
    data["scanned"] = m_scanned;
    data["checksum"] = m_checksum;
    data["size"] = m_size;
    data["hash_md5"] = m_md5;
    data["hash_sha1"] = m_sha1;
    data["hash_sha256"] = m_sha256;
    data["type"] = m_type;

    conf["data"] = nlohmann::json::array({data});

    if (m_oldData)
    {
        conf["return_old_data"] = true;
    }

    m_statementConf = std::make_unique<nlohmann::json>(conf);

}
