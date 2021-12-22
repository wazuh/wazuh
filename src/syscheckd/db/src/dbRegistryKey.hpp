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
#include "json.hpp"
#include "dbItem.hpp"

struct FimRegistryKeyDeleter
{
    void operator()(fim_entry* fimRegistryKey)
    {
        if (fimRegistryKey)
        {
            if (fimRegistryKey->registry_entry.key)
            {
                if (fimRegistryKey->registry_entry.key->gid)
                {
                    std::free(fimRegistryKey->registry_entry.key->gid);
                }

                if (fimRegistryKey->registry_entry.key->uid)
                {
                    std::free(fimRegistryKey->registry_entry.key->uid);
                }

                std::free(fimRegistryKey->registry_entry.key);
            }

            std::free(fimRegistryKey);
        }
    }
};

class RegistryKey final : public DBItem
{
    public:
        RegistryKey(fim_entry* const fim)
            : DBItem(std::to_string(fim->registry_entry.key->id)
                     , fim->registry_entry.key->scanned
                     , fim->registry_entry.key->last_event
                     , fim->registry_entry.key->checksum
                     , FIM_SCHEDULED)
        {
            m_arch = fim->registry_entry.key->arch;
            m_gid = std::atoi(fim->registry_entry.key->gid);
            m_uid = std::atoi(fim->registry_entry.key->uid);
            m_groupname = std::string(fim->registry_entry.key->group_name);
            m_path = std::string(fim->registry_entry.key->path);
            m_perm = std::string(fim->registry_entry.key->perm);
            m_username = std::string(fim->registry_entry.key->user_name);
            m_time = fim->registry_entry.key->mtime;
            createJSON();
            createFimEntry();
        }

        RegistryKey(const std::string& id,
                    const std::string& checksum,
                    const time_t& lastEvent,
                    const unsigned int& scanned,
                    const int& arch,
                    const int& gid,
                    const std::string& groupname,
                    const std::string& path,
                    const std::string& perm,
                    const unsigned int& time,
                    const int& uid,
                    const std::string& username)
            : DBItem(id, scanned, lastEvent, checksum, FIM_SCHEDULED)
            , m_arch( arch )
            , m_gid ( gid )
            , m_uid( uid )
            , m_groupname( groupname )
            , m_path( path )
            , m_perm( perm )
            , m_username( username )
            , m_time( time )
        {
            createFimEntry();
            createJSON();
        }

        RegistryKey(const nlohmann::json& fim)
            : DBItem(fim.at("id"), fim.at("scanned"), fim.at("last_event"), fim.at("checksum"), fim.at("mode"))
        {
            m_arch = fim.at("arch");
            m_gid = fim.at("gid");
            m_uid = fim.at("uid");
            m_groupname = fim.at("group_name");
            m_path = fim.at("path");
            m_perm = fim.at("perm");
            m_username = fim.at("user_name");
            m_time = fim.at("mtime");
            createFimEntry();
            m_statementConf = std::make_unique<nlohmann::json>(fim);
        }

        ~RegistryKey() = default;
        fim_entry* toFimEntry()
        {
            return m_fimEntry.get();
        };

        nlohmann::json* toJSON()
        {
            return m_statementConf.get();
        };

    private:
        int                                                 m_arch;
        int                                                 m_gid;
        int                                                 m_uid;
        std::string                                         m_groupname;
        std::string                                         m_path;
        std::string                                         m_perm;
        std::string                                         m_username;
        time_t                                              m_time;
        std::unique_ptr<fim_entry, FimRegistryKeyDeleter>   m_fimEntry;
        std::unique_ptr<nlohmann::json>                     m_statementConf;

        void createFimEntry();
        void createJSON();
};
#endif //_REGISTRYKEY_HPP
