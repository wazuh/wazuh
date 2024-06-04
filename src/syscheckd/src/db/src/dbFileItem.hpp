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

#ifndef _FILEITEM_HPP
#define _FILEITEM_HPP
#include "json.hpp"
#include "dbItem.hpp"
#include "fimCommonDefs.h"
#include "fimDBSpecialization.h"

struct FimFileDataDeleter
{
    void operator()(fim_entry* fimFile)
    {
        if (fimFile)
        {
            if (fimFile->file_entry.data)
            {
                std::free(fimFile->file_entry.data);
            }

            std::free(fimFile);
        }
    }
};

class FileItem final : public DBItem
{
    public:
        FileItem(const fim_entry* const fim, bool oldData = false)
            : DBItem(fim->file_entry.path == NULL ? "" : fim->file_entry.path
                     , fim->file_entry.data->scanned
                     , fim->file_entry.data->last_event
                     , fim->file_entry.data->checksum[0] == '\0' ? "" : fim->file_entry.data->checksum
                     , fim->file_entry.data->mode)
        {
            m_oldData = oldData;
            m_options = fim->file_entry.data->options;
            m_time = fim->file_entry.data->mtime;
            m_size = fim->file_entry.data->size;
            m_dev = fim->file_entry.data->dev;
            m_inode = fim->file_entry.data->inode;

            m_attributes = fim->file_entry.data->attributes == NULL ? "" : fim->file_entry.data->attributes;
            m_username = fim->file_entry.data->user_name == NULL ? "" : fim->file_entry.data->user_name;
            m_groupname = fim->file_entry.data->group_name == NULL ? "" : fim->file_entry.data->group_name;
            m_perm = fim->file_entry.data->perm == NULL ? "" : fim->file_entry.data->perm;

            FIMDBCreator<OS_TYPE>::encodeString(m_attributes);
            FIMDBCreator<OS_TYPE>::encodeString(m_username);
            FIMDBCreator<OS_TYPE>::encodeString(m_groupname);
            FIMDBCreator<OS_TYPE>::encodeString(m_perm);

            m_md5 = fim->file_entry.data->hash_md5[0] == '\0' ? "" : fim->file_entry.data->hash_md5;
            m_sha1 = fim->file_entry.data->hash_sha1[0] == '\0' ? "" : fim->file_entry.data->hash_sha1;
            m_sha256 = fim->file_entry.data->hash_sha256[0] == '\0' ? "" : fim->file_entry.data->hash_sha256;
            m_uid = fim->file_entry.data->uid == NULL ? "" : fim->file_entry.data->uid;
            m_gid = fim->file_entry.data->gid == NULL ? "" : fim->file_entry.data->gid;
            createJSON();
            createFimEntry();
        };

        FileItem(const nlohmann::json& fim)
            : DBItem(fim.at("path"), fim.at("scanned"), fim.at("last_event"), fim.at("checksum"), fim.at("mode"))
        {
            m_options = fim.at("options");
            m_time = fim.at("mtime");
            m_size = fim.at("size");
            m_dev = fim.at("dev");
            m_inode = fim.at("inode");
            m_attributes = fim.at("attributes");
            m_gid = fim.at("gid");
            m_groupname = fim.at("group_name");
            m_md5 = fim.at("hash_md5");
            m_perm = fim.at("perm");
            m_sha1 = fim.at("hash_sha1");
            m_sha256 = fim.at("hash_sha256");
            m_uid = fim.at("uid");
            m_username = fim.at("user_name");

            createFimEntry();
            m_statementConf = std::make_unique<nlohmann::json>(fim);
        };

        ~FileItem() = default;
        fim_entry* toFimEntry()
        {
            return m_fimEntry.get();
        };

        const nlohmann::json* toJSON() const
        {
            return m_statementConf.get();
        };

    private:
        int                                             m_options;
        std::string                                     m_gid;
        std::string                                     m_uid;
        unsigned long int                               m_size;
        unsigned long int                               m_dev;
        unsigned long long int                          m_inode;
        time_t                                          m_time;
        std::string                                     m_attributes;
        std::string                                     m_groupname;
        std::string                                     m_md5;
        std::string                                     m_perm;
        std::string                                     m_sha1;
        std::string                                     m_sha256;
        std::string                                     m_username;
        std::unique_ptr<fim_entry, FimFileDataDeleter>  m_fimEntry;
        std::unique_ptr<nlohmann::json>                 m_statementConf;

        void createFimEntry();
        void createJSON();
};
#endif //_FILEITEM_HPP
