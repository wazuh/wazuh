/*
 * Wazuh Syscheckd
 * Copyright (C) 2015-2021, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FILEITEM_HPP
#define _FILEITEM_HPP
#include "json.hpp"
#include "dbItem.hpp"

class FileItem final : public DBItem {
public:
    FileItem(const fim_entry &file_entry) : DBItem(std::string(file_entry.file_entry.path),
                                                               file_entry.file_entry.data->scanned,
                                                               file_entry.file_entry.data->last_event,
                                                               file_entry.file_entry.data->checksum,
                                                               file_entry.file_entry.data->mode)
                                                               {
                                                                    m_options = file_entry.file_entry.data->options;
                                                                    m_time = file_entry.file_entry.data->mtime;
                                                                    m_size = file_entry.file_entry.data->size;
                                                                    m_dev = file_entry.file_entry.data->dev;
                                                                    m_inode = file_entry.file_entry.data->inode;
                                                                    m_attributes = std::string(file_entry.file_entry.data->attributes);
                                                                    m_gid = atoi(file_entry.file_entry.data->gid);
                                                                    m_groupname = std::string(file_entry.file_entry.data->group_name);
                                                                    m_md5 = std::string(file_entry.file_entry.data->hash_md5);
                                                                    m_perm = std::string(file_entry.file_entry.data->perm);
                                                                    m_sha1 = std::string(file_entry.file_entry.data->hash_sha1);
                                                                    m_sha256 = std::string(file_entry.file_entry.data->hash_sha256);
                                                                    m_uid = atoi(file_entry.file_entry.data->uid);
                                                                    m_username = std::string(file_entry.file_entry.data->user_name);
                                                                    m_fimEntry = std::make_unique<fim_entry>(file_entry);
                                                               }
    FileItem(const std::string &path,
             const std::string &checksum,
             const time_t &lastEvent,
             const fim_event_mode &mode,
             const unsigned int &scanned,
             const int &options,
             const int &uid,
             const int &gid,
             const unsigned int &time,
             const unsigned int &size,
             const unsigned long &dev,
             const unsigned long int &inode,
             const std::string &attributes,
             const std::string &groupname,
             const std::string &md5,
             const std::string &perm,
             const std::string &sha1,
             const std::string &sha256,
             std::string &username)
             : DBItem(path, scanned, lastEvent, checksum, mode)
             , m_options( options )
             , m_gid ( gid )
             , m_uid( uid )
             , m_size( size )
             , m_dev( dev )
             , m_inode( inode )
             , m_time( time )
             , m_attributes( attributes )
             , m_groupname( groupname )
             , m_md5( md5 )
             , m_perm( perm )
             , m_sha1( sha1)
             , m_sha256( sha256 )
             , m_username( username )
             {
                toFimEntry();
             }
    ~FileItem();
    fim_entry* fimEntry() { return m_fimEntry.get(); };
    nlohmann::json* toJSON();

private:
    int                         m_options;
    int                         m_gid;
    int                         m_uid;
    unsigned int                m_size;
    unsigned long int           m_dev;
    unsigned long int           m_inode;
    time_t                      m_time;
    std::string                 m_attributes;
    std::string                 m_groupname;
    std::string                 m_md5;
    std::string                 m_perm;
    std::string                 m_sha1;
    std::string                 m_sha256;
    std::string                 m_username;
    std::unique_ptr<fim_entry>  m_fimEntry;
    
    void toFimEntry();
};
#endif //_FILEITEM_HPP
