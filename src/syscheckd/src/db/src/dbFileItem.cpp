/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * September 24, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "dbFileItem.hpp"

void FileItem::createFimEntry()
{
    fim_entry* fim = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));
    fim_file_data* data = reinterpret_cast<fim_file_data*>(std::calloc(1, sizeof(fim_file_data)));

    if (fim)
    {
        fim->type = FIM_TYPE_FILE;
#ifdef WIN32
        m_pathAnsi = Utils::EncodingWindowsHelper::stringUTF8ToStringAnsi(m_identifier);
        fim->file_entry.path = const_cast<char*>(m_pathAnsi.c_str());
#else
        fim->file_entry.path = const_cast<char*>(m_identifier.c_str());
#endif

        if (data)
        {
            data->size = m_size;
            data->perm = const_cast<char*>(m_perm.c_str());
            data->attributes = const_cast<char*>(m_attributes.c_str());
            data->uid = const_cast<char*>(m_uid.c_str());
            data->gid = const_cast<char*>(m_gid.c_str());
            data->user_name = const_cast<char*>(m_username.c_str());
            data->group_name = const_cast<char*>(m_groupname.c_str());
            data->mtime = m_time;
            data->inode = m_inode;
            std::snprintf(data->hash_md5, sizeof(data->hash_md5), "%s", m_md5.c_str());
            std::snprintf(data->hash_sha1, sizeof(data->hash_sha1), "%s", m_sha1.c_str());
            std::snprintf(data->hash_sha256, sizeof(data->hash_sha256), "%s", m_sha256.c_str());
            data->mode = m_mode;
            data->last_event = m_lastEvent;
            data->dev = m_dev;
            data->scanned = m_scanned;
            data->options = m_options;
            std::snprintf(data->checksum, sizeof(data->checksum), "%s", m_checksum.c_str());

            fim->file_entry.data = data;
            m_fimEntry = std::unique_ptr<fim_entry, FimFileDataDeleter>(fim);
        }
        // LCOV_EXCL_START
        else
        {
            throw std::runtime_error("The memory for fim_file_data could not be allocated.");
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

void FileItem::createJSON()
{
    nlohmann::json conf;
    nlohmann::json data;
    nlohmann::json options;

    conf["table"] = FIMDB_FILE_TABLE_NAME;
    data["path"] = m_identifier;
    data["mode"] = m_mode;
    data["last_event"] = m_lastEvent;
    data["scanned"] = m_scanned;
    data["options"] = m_options;
    data["checksum"] = m_checksum;
    data["dev"] = m_dev;
    data["inode"] = m_inode;
    data["size"] = m_size;
    data["perm"] = m_perm;
    data["attributes"] = m_attributes;
    data["uid"] = m_uid;
    data["gid"] = m_gid;
    data["user_name"] = m_username;
    data["group_name"] = m_groupname;
    data["hash_md5"] = m_md5;
    data["hash_sha1"] = m_sha1;
    data["hash_sha256"] = m_sha256;
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
