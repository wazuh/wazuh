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

#ifndef _DBFILEITEM_HPP
#define _DBFILEITEM_HPP
#include "shared.h"
#include "db_item.hpp"

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
    FileItem();
    ~FileItem();
    fim_entry* toFimEntry();
    nlohmann::json* toJSON();

private:
    int             m_size;
    int             m_dev;
    int             m_options;
    int             m_uid;
    int             m_inode;
    int             m_gid;
    time_t          m_time;
    std::string     m_username;
    std::string     m_perm;
    std::string     m_attributes;
    std::string     m_groupname;
    std::string     m_md5;
    std::string     m_sha1;
    std::string     m_sha256;
};
#endif //_DBFILEITEM_HPP