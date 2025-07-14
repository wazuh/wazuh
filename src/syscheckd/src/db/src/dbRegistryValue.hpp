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

#ifndef _REGISTRYVALUE_HPP
#define _REGISTRYVALUE_HPP

#include "json.hpp"
#include "dbItem.hpp"
#include "fimDBSpecialization.h"

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
        RegistryValue(const fim_entry* const fim, bool oldData = false)
            : DBItem(fim->registry_entry.value->value ? fim->registry_entry.value->value : ""
                     , fim->registry_entry.value->checksum)
        {
            m_oldData = oldData;
            m_path = fim->registry_entry.value->path ? fim->registry_entry.value->path : "";
            FIMDBCreator<OS_TYPE>::encodeString(m_path);
            m_architecture = fim->registry_entry.value->architecture;
            m_size = fim->registry_entry.value->size;
            m_type = fim->registry_entry.value->type;
            m_md5 = fim->registry_entry.value->hash_md5;
            m_sha1 = fim->registry_entry.value->hash_sha1;
            m_sha256 = fim->registry_entry.value->hash_sha256;
            createJSON();
            createFimEntry();
        }

        RegistryValue(const nlohmann::json& fim, bool oldData = false)
            : DBItem(fim.at("value"), fim.at("checksum"))
        {
            m_oldData = oldData;
            m_size = fim.at("size");
            m_type = fim.at("type");
            m_md5 = fim.at("hash_md5");
            m_sha1 = fim.at("hash_sha1");
            m_sha256 = fim.at("hash_sha256");
            m_architecture = fim.at("architecture");
            m_path = fim.at("path");
            createFimEntry();
            createJSON();
        }

        ~RegistryValue() = default;
        fim_entry* toFimEntry()
        {
            return m_fimEntry.get();
        };

        const nlohmann::json* toJSON() const
        {
            return m_statementConf.get();
        };

    private:
        unsigned long long int                              m_size;
        unsigned int                                        m_type;
        std::string                                         m_path;
        int                                                 m_architecture;
        std::string                                         m_md5;
        std::string                                         m_sha1;
        std::string                                         m_sha256;
        std::unique_ptr<fim_entry, FimRegistryValueDeleter> m_fimEntry;
        std::unique_ptr<nlohmann::json>                     m_statementConf;

        void createFimEntry();
        void createJSON();
};
#endif //_REGISTRYVALUE_HPP
