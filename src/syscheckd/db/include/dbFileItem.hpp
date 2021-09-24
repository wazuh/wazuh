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

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

class EXPORTED FileItem : public DBItem {
public:
    FileItem(fim_entry*);
    ~FileItem();
    fim_entry* toFimEntry();
    nlohmann::json* toJSON();

private:
    int                     m_options;
    int                     m_gid;
    int                     m_uid;
    unsigned int            m_size;
    unsigned long int       m_dev;
    unsigned long int       m_inode;
    time_t                  m_time;
    std::string             m_attributes;
    std::string             m_groupname;
    std::string             m_md5;
    std::string             m_perm;
    std::string             m_sha1;
    std::string             m_sha256;
    std::string             m_username;
};
#endif //_FILEITEM_HPP
