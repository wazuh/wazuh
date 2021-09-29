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

class RegistryKey final : public DBItem {
public:
    RegistryKey();
    ~RegistryKey();
    fim_entry* toFimEntry();
    nlohmann::json* toJSON();

private:
    int             m_arch;
    int             m_gid;
    int             m_uid;
    std::string     m_groupname;
    std::string     m_path;
    std::string     m_perm;
    std::string     m_username;
    time_t          m_time;
};
#endif //_REGISTRYKEY_HPP
