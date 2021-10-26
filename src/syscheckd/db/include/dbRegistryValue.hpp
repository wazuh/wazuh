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
#include "json.hpp"
#include "dbItem.hpp"

struct FimRegistryValueDeleter
{
    void operator()(fim_entry* fimRegistryValue)
    {
        if (fimRegistryValue)
        {
            if (fimRegistryValue->registry_entry.value)
            {
                std::free(fimRegistryValue->registry_entry.value);
            }

            std::free(fimRegistryValue);
        }
    }
};

class RegistryValue final : public DBItem
{
    public:
        RegistryValue(fim_entry* const fim)
            : DBItem(std::string(fim->registry_entry.value->name)
                     , fim->registry_entry.value->scanned
                     , fim->registry_entry.value->last_event
                     , fim->registry_entry.value->checksum
                     , fim->registry_entry.value->mode)
        {
            m_keyUid = fim->registry_entry.value->id;
            m_registryKey = 0;
            m_size = fim->registry_entry.value->size;
            m_type = fim->registry_entry.value->type;
            m_md5 = std::string(fim->registry_entry.value->hash_md5);
            m_sha1 = std::string(fim->registry_entry.value->hash_sha1);
            m_sha256 = std::string(fim->registry_entry.value->hash_sha256);
            createJSON();
            createFimEntry();
        }

        RegistryValue(const std::string& name,
                      const std::string& checksum,
                      const time_t& lastEvent,
                      const unsigned int& scanned,
                      const fim_event_mode& mode,
                      const unsigned int& registryKey,
                      const unsigned int& rowID,
                      const std::string& md5,
                      const std::string& sha1,
                      const std::string& sha256,
                      const unsigned int& size,
                      const unsigned int& type)
            : DBItem(name, scanned, lastEvent, checksum, mode)
            , m_keyUid( rowID )
            , m_registryKey ( registryKey )
            , m_size( size )
            , m_type( type )
            , m_md5( md5 )
            , m_sha1( sha1 )
            , m_sha256( sha256 )
        {
            createFimEntry();
            createJSON();
        }

        RegistryValue(const nlohmann::json& fim)
            : DBItem(fim.at("name"), fim.at("scanned"), fim.at("last_event"), fim.at("checksum"), fim.at("mode"))
        {
            m_keyUid = fim.at("id");
            m_registryKey = 0;
            m_size = fim.at("size");
            m_type = fim.at("type");
            m_md5 = fim.at("hash_md5");
            m_sha1 = fim.at("hash_sha1");
            m_sha256 = fim.at("hash_sha256");
            createFimEntry();
            m_statementConf = std::make_unique<nlohmann::json>(fim);
        }

        ~RegistryValue() = default;
        fim_entry* toFimEntry()
        {
            return m_fimEntry.get();
        };

        nlohmann::json* toJSON()
        {
            return m_statementConf.get();
        };

    private:
        unsigned int                                        m_keyUid;
        unsigned int                                        m_registryKey;
        unsigned int                                        m_size;
        unsigned int                                        m_type;
        std::string                                         m_md5;
        std::string                                         m_sha1;
        std::string                                         m_sha256;
        std::unique_ptr<fim_entry, FimRegistryValueDeleter> m_fimEntry;
        std::unique_ptr<nlohmann::json>                     m_statementConf;

        void createFimEntry();
        void createJSON();
};
#endif //_REGISTRYVALUE_HPP
