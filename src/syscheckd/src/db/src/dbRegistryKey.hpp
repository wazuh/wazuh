/*
 * Wazuh Syscheck
 * Copyright (C) 2015, Wazuh Inc.
 * September 23, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REGISTRYKEY_HPP
#define _REGISTRYKEY_HPP
#include "json.hpp"
#include "dbItem.hpp"
#include "fimDBSpecialization.h"

struct FimRegistryKeyDeleter
{
    void operator()(fim_entry* fimRegistryKey)
    {
        if (fimRegistryKey)
        {
            if (fimRegistryKey->registry_entry.key)
            {
                std::free(fimRegistryKey->registry_entry.key);
            }

            std::free(fimRegistryKey);
        }
    }
};

class RegistryKey final : public DBItem
{
    public:
        RegistryKey(const fim_entry* const fim, bool old_data = false)
            : DBItem(std::string(fim->registry_entry.key->path)
                     , fim->registry_entry.key->checksum)
        {
            m_oldData = old_data;
            m_architecture = fim->registry_entry.key->architecture;
            m_gid = fim->registry_entry.key->gid ? fim->registry_entry.key->gid : "";
            m_uid = fim->registry_entry.key->uid ? fim->registry_entry.key->uid : "";
            m_group = fim->registry_entry.key->group ? fim->registry_entry.key->group : "";
            m_permissions = fim->registry_entry.key->permissions ? fim->registry_entry.key->permissions : "";
            m_owner = fim->registry_entry.key->owner ? fim->registry_entry.key->owner : "";

            FIMDBCreator<OS_TYPE>::encodeString(m_group);
            FIMDBCreator<OS_TYPE>::encodeString(m_permissions);
            FIMDBCreator<OS_TYPE>::encodeString(m_owner);

            m_time = fim->registry_entry.key->mtime;
            createJSON();
            createFimEntry();
        }

        RegistryKey(const nlohmann::json& fim, bool oldData = false)
            : DBItem(fim.at("path"), fim.at("checksum"))
        {
            m_oldData = oldData;
            m_architecture = fim.at("architecture");
            m_gid = fim.at("gid");
            m_uid = fim.at("uid");
            m_group = fim.at("group");
            m_permissions = fim.at("permissions");
            m_owner = fim.at("owner");
            m_time = fim.at("mtime");
            createFimEntry();
            createJSON();
        }

        ~RegistryKey() = default;
        fim_entry* toFimEntry()
        {
            return m_fimEntry.get();
        };

        const nlohmann::json* toJSON() const
        {
            return m_statementConf.get();
        };

    private:
        int                                                 m_architecture;
        std::string                                         m_gid;
        std::string                                         m_uid;
        std::string                                         m_group;
        std::string                                         m_permissions;
        std::string                                         m_owner;
        time_t                                              m_time;
        std::unique_ptr<fim_entry, FimRegistryKeyDeleter>   m_fimEntry;
        std::unique_ptr<nlohmann::json>                     m_statementConf;

        void createFimEntry();
        void createJSON();
};
#endif //_REGISTRYKEY_HPP
