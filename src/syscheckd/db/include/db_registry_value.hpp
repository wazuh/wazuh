/**
 * @file db_registry_value.hpp
 * @brief
 * @date 2021-09-22
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef _REGISTRYVALUE_HPP
#define _REGISTRYVALUE_HPP
#include "shared.h"
#include "db_item.hpp"
#include "db_registry_key.hpp"

class final RegistryValue : public DBItem {
public:
    RegistryValue();
    ~RegistryValue();
    fim_entry* toFimEntry();
    nlohmann::json* toJSON();

private:
    int m_type;
    int m_keyUid;
    int m_size;
    RegistryKey* m_key;
    std::string m_md5;
    std::string m_sha1;
    std::string m_sha256;
};
}
#endif //_REGISTRYVALUE_HPP