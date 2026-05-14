/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
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
    fim_entry* fim = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));
    fim_registry_value_data* value = reinterpret_cast<fim_registry_value_data*>(std::calloc(1, sizeof(fim_registry_value_data)));

    if (fim)
    {
        fim->type = FIM_TYPE_REGISTRY;

        if (value)
        {
            value->path = const_cast<char*>(m_path.c_str());
            value->hash_full_path = const_cast<char*>(m_hashpath.c_str());
            value->size = m_size;
            value->name = const_cast<char*>(m_identifier.c_str());
            std::snprintf(value->hash_md5, sizeof(value->hash_md5), "%s", m_md5.c_str());
            std::snprintf(value->hash_sha1, sizeof(value->hash_sha1), "%s", m_sha1.c_str());
            std::snprintf(value->hash_sha256, sizeof(value->hash_sha256), "%s", m_sha256.c_str());
            value->mode = m_mode;
            value->last_event = m_lastEvent;
            value->scanned = m_scanned;
            std::snprintf(value->checksum, sizeof(value->checksum), "%s", m_checksum.c_str());
            fim->registry_entry.value = value;
            m_fimEntry = std::unique_ptr<fim_entry, FimRegistryValueDeleter>(fim);
        }
        // LCOV_EXCL_START
        else
        {
            throw std::runtime_error("The memory for fim_registry_value_data could not be allocated.");
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

void RegistryValue::createJSON()
{

    nlohmann::json conf;
    nlohmann::json data;
    nlohmann::json options;

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
