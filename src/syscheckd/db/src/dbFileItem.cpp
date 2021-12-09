/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
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
    fim_entry* fim = reinterpret_cast<fim_entry*>(std::calloc(1, sizeof(fim_entry)));;
    fim_file_data* data = reinterpret_cast<fim_file_data*>(std::calloc(1, sizeof(fim_file_data)));

    fim->type = FIM_TYPE_FILE;
    fim->file_entry.path = const_cast<char*>(m_identifier.c_str());
    data->size = m_size;
    data->perm = const_cast<char*>(m_perm.c_str());
    data->attributes = const_cast<char*>(m_attributes.c_str());
    data->uid = reinterpret_cast<char*>(std::calloc(1, sizeof(char*)));
    std::strncpy(data->uid, std::to_string(m_uid).c_str(), sizeof(std::to_string(m_uid).size()));
    data->gid = reinterpret_cast<char*>(std::calloc(1, sizeof(char*)));
    std::strncpy(data->gid, std::to_string(m_gid).c_str(), sizeof(std::to_string(m_gid).size()));
    data->user_name = const_cast<char*>(m_username.c_str());
    data->group_name = const_cast<char*>(m_groupname.c_str());
    data->mtime = m_time;
    data->inode = m_inode;
    std::strncpy(data->hash_md5, m_md5.c_str(), sizeof(data->hash_md5));
    std::strncpy(data->hash_sha1, m_sha1.c_str(), sizeof(data->hash_sha1));
    std::strncpy(data->hash_sha256, m_sha256.c_str(), sizeof(data->hash_sha256));
    data->mode = m_mode;
    data->last_event = m_lastEvent;
    data->dev = m_dev;
    data->scanned = m_scanned;
    data->options = m_options;
    std::strncpy(data->checksum, m_checksum.c_str(), sizeof(data->checksum));
    fim->file_entry.data = data;
    m_fimEntry = std::unique_ptr<fim_entry, FimFileDataDeleter>(fim);
}

void FileItem::createJSON()
{
    nlohmann::json conf;
    nlohmann::json data;

    conf["table"] = FIMBD_FILE_TABLE_NAME;
    data.push_back(nlohmann::json::object_t::value_type("path", m_identifier));
    data.push_back(nlohmann::json::object_t::value_type("mode", m_mode));
    data.push_back(nlohmann::json::object_t::value_type("last_event", m_lastEvent));
    data.push_back(nlohmann::json::object_t::value_type("scanned", m_scanned));
    data.push_back(nlohmann::json::object_t::value_type("options", m_options));
    data.push_back(nlohmann::json::object_t::value_type("checksum", m_checksum));
    data.push_back(nlohmann::json::object_t::value_type("dev", m_dev));
    data.push_back(nlohmann::json::object_t::value_type("inode", m_inode));
    data.push_back(nlohmann::json::object_t::value_type("size", m_size));
    data.push_back(nlohmann::json::object_t::value_type("perm", m_perm));
    data.push_back(nlohmann::json::object_t::value_type("attributes", m_attributes));
    data.push_back(nlohmann::json::object_t::value_type("uid", m_uid));
    data.push_back(nlohmann::json::object_t::value_type("gid", m_gid));
    data.push_back(nlohmann::json::object_t::value_type("user_name", m_username));
    data.push_back(nlohmann::json::object_t::value_type("group_name", m_groupname));
    data.push_back(nlohmann::json::object_t::value_type("hash_md5", m_md5));
    data.push_back(nlohmann::json::object_t::value_type("hash_sha1", m_sha1));
    data.push_back(nlohmann::json::object_t::value_type("hash_sha256", m_sha256));
    data.push_back(nlohmann::json::object_t::value_type("mtime", m_time));
    conf["data"] = nlohmann::json::array({data});
    m_statementConf = std::make_unique<nlohmann::json>(conf);
}
