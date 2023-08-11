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
                     , fim->registry_entry.key->scanned
                     , fim->registry_entry.key->last_event
                     , fim->registry_entry.key->checksum
                     , FIM_SCHEDULED)
        {
            m_oldData = old_data;
            m_arch = fim->registry_entry.key->arch;
            m_gid = fim->registry_entry.key->gid ? fim->registry_entry.key->gid : "";
            m_uid = fim->registry_entry.key->uid ? fim->registry_entry.key->uid : "";
            m_groupname = fim->registry_entry.key->group_name ? fim->registry_entry.key->group_name : "";
            m_perm = fim->registry_entry.key->perm ? fim->registry_entry.key->perm : "";
            m_username = fim->registry_entry.key->user_name ? fim->registry_entry.key->user_name : "";

            FIMDBCreator<OS_TYPE>::encodeString(m_groupname);
            FIMDBCreator<OS_TYPE>::encodeString(m_perm);
            FIMDBCreator<OS_TYPE>::encodeString(m_username);

            m_time = fim->registry_entry.key->mtime;
            m_hashpath = fim->registry_entry.key->hash_full_path;
            createJSON();
            createFimEntry();
        }

        RegistryKey(const nlohmann::json& fim, bool oldData = false)
            : DBItem(fim.at("path"), fim.at("scanned"), fim.at("last_event"), fim.at("checksum"), fim.at("mode"))
        {
            m_oldData = oldData;
            m_arch = fim.at("arch");
            m_gid = fim.at("gid");
            m_uid = fim.at("uid");
            m_groupname = fim.at("group_name");
            m_perm = fim.at("perm");
            m_username = fim.at("user_name");
            m_time = fim.at("mtime");
            m_hashpath = fim.at("hash_full_path");
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
        int                                                 m_arch;
        std::string                                         m_gid;
        std::string                                         m_uid;
        std::string                                         m_groupname;
        std::string                                         m_perm;
        std::string                                         m_username;
        time_t                                              m_time;
        std::unique_ptr<fim_entry, FimRegistryKeyDeleter>   m_fimEntry;
        std::unique_ptr<nlohmann::json>                     m_statementConf;
        std::string                                         m_hashpath;

        void createFimEntry();
        void createJSON();
};
#endif //_REGISTRYKEY_HPP
