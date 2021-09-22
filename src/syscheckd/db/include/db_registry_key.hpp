/**
 * @file db_registry_key.hpp
 * @brief
 * @date 2021-09-22
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef _REGISTRYKEY_HPP
#define _REGISTRYKEY_HPP
#include "shared.h"
#include "db_item.hpp"

class final RegistryKey : public DBItem {
public:
    RegistryKey();
    ~RegistryKey();
    fim_entry* toFimEntry();
    nlohmann::json* toJSON();

private:
    int m_uid;
    int m_gid;
    int m_time;
    std::string m_perms;
    std::string m_username;
    std::string m_groupname;
    std::string m_arch;
};
}
#endif //_REGISTRYKEY_HPP