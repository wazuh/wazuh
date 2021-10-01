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
#include "syscheck.h"

void FileItem::createFimEntry() {
    fim_entry *fim = nullptr;
    fim_file_data *data = reinterpret_cast<fim_file_data*>(calloc(1, sizeof(fim_file_data)));

    fim->type = FIM_TYPE_FILE;
    fim->file_entry.path = const_cast<char*>(m_identifier.c_str());
    data->size = m_size;
    data->perm = const_cast<char*>(m_perm.c_str());
    data->attributes = const_cast<char*>(m_attributes.c_str());
    data->uid = const_cast<char*>(std::to_string(m_uid).c_str());
    data->gid = const_cast<char*>(std::to_string(m_gid).c_str());
    data->user_name = const_cast<char*>(m_username.c_str());
    data->group_name = const_cast<char*>(m_groupname.c_str());
    data->mtime = m_time;
    data->inode = m_inode;
    strncpy(data->hash_md5, m_md5.c_str(), sizeof(data->hash_md5));
    strncpy(data->hash_sha1, m_sha1.c_str(), sizeof(data->hash_sha1));
    strncpy(data->hash_sha256, m_sha256.c_str(), sizeof(data->hash_sha256));
    data->mode = m_mode;
    data->last_event = m_lastEvent;
    data->dev = m_dev;
    data->scanned = m_scanned;
    data->options = m_options;
    strncpy(data->checksum, m_checksum.c_str(), sizeof(data->checksum));
    fim->file_entry.data = data;
    m_fimEntry = std::unique_ptr<fim_entry, FimFileDataDeleter>(fim);
}

void FileItem::createJSON() {
    nlohmann::json conf;

    conf["path"] = m_identifier;
    conf["mode"] = m_mode;
    conf["last_event"] = m_lastEvent;
    conf["scanned"] = m_scanned;
    conf["options"] = m_options;
    conf["checksum"] = m_checksum;
    conf["dev"] = m_dev;
    conf["inode"] = m_inode;
    conf["size"] = m_size;
    conf["perm"] = m_perm;
    conf["attributes"] = m_attributes;
    conf["uid"] = m_uid;
    conf["gid"] = m_gid;
    conf["user_name"] = m_username;
    conf["group_name"] = m_groupname;
    conf["hash_md5"] = m_md5;
    conf["hash_sha1"] = m_sha1;
    conf["hash_sha256"] = m_sha256;
    conf["mtime"] = m_time;
    m_statementConf = std::make_unique<nlohmann::json>(conf);
}

nlohmann::json* FileItem::toJSON() {
    createJSON();

    return m_statementConf.get();
}
