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

FileItem::FileItem(fim_entry* file_entry) {
    m_identifier = std::string(fim_entry->file_entry.path);
    m_checksum = std::string(file_entry->file_entry.data->checksum);
    m_lastEvent = file_entry->file_entry.data->last_event;
    m_mode = file_entry->file_entry.data->mode;
    m_scanned = file_entry->file_entry.data->scanned;
    m_options = file_entry->file_entry.data->options;
    m_time = file_entry->file_entry.data->mtime;
    m_size = file_entry->file_entry.data->size;
    m_dev = file_entry->file_entry.data->dev;
    m_inode = file_entry->file_entry.data->inode;
    m_attributes = std::string(file_entry->file_entry.data->attributes);
    m_gid = atoi(file_entry->file_entry.data->gid);
    m_groupname = std::string(file_entry->file_entry.data->group_name);
    m_md5 = std::string(file_entry->file_entry.data->hash_md5);
    m_perm = std::string(file_entry->file_entry.data->perm); 
    m_sha1 = std::string(file_entry->file_entry.data->hash_sha1);
    m_sha256 = std::string(file_entry->file_entry.data->hash_sha256);
    m_uid = atoi(file_entry->file_entry.data->uid);
    m_username = std::string(file_entry->file_entry.data->user_name);
}

FileItem::FileItem(std::string path,
                   std::string checksum,
                   time_t lastEvent,
                   int mode,
                   unsigned int scanned,
                   int options,
                   unsigned int time,
                   unsigned int size,
                   unsigned long dev,
                   unsigned long int inode,
                   std::string attributes,
                   int gid,
                   std::string groupname,
                   std::string md5,
                   std::string perm,
                   std::string sha1,
                   std::string sha256,
                   int uid,
                   std::string username) {
    m_identifier = path;
    m_checksum = checksum;
    m_lastEvent = lastEvent;
    m_mode = mode;
    m_scanned = scanned;
    m_options = options;
    m_time = time;
    m_size = size;
    m_dev = dev;
    m_inode = inode;
    m_attributes = attributes;
    m_gid = gid;
    m_groupname = groupname;
    m_md5 = md5;
    m_perm = perm; 
    m_sha1 = sha1;
    m_sha256 = sha256;
    m_uid = uid;
    m_username = username;
}

nlohmann::json* FileItem::toJSON() {
    nlohmann::json file;

    file["path"] = m_identifier;
    file["mode"] = m_mode;
    file["last_event"] = m_lastEvent;
    file["scanned"] = m_scanned;
    file["options"] = m_options;
    file["checksum"] = m_checksum;
    file["dev"] = m_dev;
    file["inode"] = m_inode;
    file["size"] = m_size;
    file["perm"] = m_perm;
    file["attributes"] = m_attributes;
    file["uid"] = m_uid;
    file["gid"] = m_gid;
    file["user_name"] = m_username;
    file["group_name"] = m_groupname;
    file["hash_md5"] = m_md5;
    file["hash_sha1"] = m_sha1;
    file["hash_sha256"] = m_sha256;
    file["mtime"] = m_time;

    return &file;
}

fim_entry* FileItem::toFimEntry(){
    fim_entry fim;

    fim.file_entry.path = const_cast<char*>(m_identifier.c_str());
    fim.file_entry.data->size = m_size;
    fim.file_entry.data->perm = const_cast<char*>(m_perm.c_str());
    fim.file_entry.data->attributes = const_cast<char*>(m_attributes.c_str());
    fim.file_entry.data->uid = const_cast<char*>(std::to_string(m_uid).c_str());
    fim.file_entry.data->gid = const_cast<char*>(std::to_string(m_gid).c_str());
    fim.file_entry.data->user_name = const_cast<char*>(m_username.c_str());
    fim.file_entry.data->group_name = const_cast<char*>(m_groupname.c_str());
    fim.file_entry.data->mtime = m_time;
    fim.file_entry.data->inode = m_inode;
    fim.file_entry.data->hash_md5 = const_cast<char*>(m_md5.c_str());
    fim.file_entry.data->hash_sha1 = const_cast<char*>(m_sha1.c_str());
    fim.file_entry.data->hash_sha256 = const_cast<char*>(m_sha256.c_str());
    fim.file_entry.data->mode = m_mode;
    fim.file_entry.data->last_event = m_lastEvent;
    fim.file_entry.data->dev = m_dev;
    fim.file_entry.data->scanned = m_scanned;
    fim.file_entry.data->options = m_options;
    fim.file_entry.data->checksum = const_cast<char*>(m_checksum.c_str());

    return &fim;
}