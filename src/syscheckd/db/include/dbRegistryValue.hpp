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
#include "dbItem.hpp"
#include "dbRegistryValue.hpp"

class RegistryValue final : public DBItem {
public:
    RegistryValue();
    ~RegistryValue();
    fim_entry* toFimEntry();
    nlohmann::json* toJSON();

private:
    int             m_type;
    int             m_keyUid;
    int             m_size;
    std::string     m_registryKey;
    std::string     m_md5;
    std::string     m_sha1;
    std::string     m_sha256;
};
#endif //_REGISTRYVALUE_HPP
