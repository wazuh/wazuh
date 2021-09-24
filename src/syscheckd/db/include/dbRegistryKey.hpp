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

#ifndef _REGISTRYKEY_HPP
#define _REGISTRYKEY_HPP
#include "shared.h"
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

class EXPORTED RegistryKey : public DBItem {
public:
    RegistryKey();
    ~RegistryKey();
    fim_entry* toFimEntry();
    nlohmann::json* toJSON();

private:
    int             m_uid;
    int             m_gid;
    int             m_time;
    std::string     m_perms;
    std::string     m_username;
    std::string     m_groupname;
    std::string     m_arch;
};
#endif //_REGISTRYKEY_HPP
