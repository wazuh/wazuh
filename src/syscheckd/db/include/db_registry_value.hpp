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

#ifndef _REGISTRYVALUE_HPP
#define _REGISTRYVALUE_HPP
#include "shared.h"
#include "db_item.hpp"
#include "db_registry_key.hpp"

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

class EXPORTED RegistryValue : public DBItem {
public:
    RegistryValue();
    ~RegistryValue();
    fim_entry* toFimEntry();
    nlohmann::json* toJSON();

private:
    int             m_type;
    int             m_keyUid;
    int             m_size;
    RegistryKey*    m_key;
    std::string     m_md5;
    std::string     m_sha1;
    std::string     m_sha256;
};
#endif //_REGISTRYVALUE_HPP