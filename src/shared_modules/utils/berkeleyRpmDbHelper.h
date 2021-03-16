/*
 * Wazuh shared modules utils
 * Copyright (C) 2015-2021, Wazuh Inc.
 * March 15, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BERKELEY_RPM_DB_HELPER_H
#define _BERKELEY_RPM_DB_HELPER_H

#include <string>
#include <memory>
#include <map>
#include <vector>
#include <algorithm>
#include <cstring>
#include "db.h"

#define TAG_NAME        1000
#define TAG_VERSION     1001
#define TAG_RELEASE     1002
#define TAG_EPOCH       1003
#define TAG_SUMMARY     1004
#define TAG_ITIME       1008
#define TAG_SIZE        1009
#define TAG_VENDOR      1011
#define TAG_GROUP       1016
#define TAG_SOURCE      1044
#define TAG_ARCH        1022

constexpr auto RPM_DATABASE {"/var/lib/rpm/Packages"};
constexpr auto FIRST_ENTRY_OFFSET { 8 };
constexpr auto ENTRY_SIZE { 16 };

namespace Utils
{
    struct BerkeleyRpmDbDeleter
    {
        void operator()(DB * db)
        {
            db->close(db, 0);
        }
        void operator()(DBC * cursor)
        {
            cursor->c_close(cursor);
        }
    };

    struct BerkeleyHeaderEntry
    {
        std::string tag;
        int type;
        int offset;
        int count;
    };

    const std::map<int32_t, std::string> TAG_NAMES =
    {
        { TAG_NAME, "name" },
        { TAG_ARCH, "architecture" },
        { TAG_SUMMARY, "description" },
        { TAG_SIZE, "size" },
        { TAG_EPOCH, "epoch" },
        { TAG_RELEASE, "release" },
        { TAG_VERSION, "version" },
        { TAG_VENDOR, "vendor" },
        { TAG_ITIME, "install_time" },
        { TAG_GROUP, "group" }
    };

    class BerkeleyRpmDBWrapper
    {
        private:
            std::unique_ptr<DB, BerkeleyRpmDbDeleter>  m_db;
            std::unique_ptr<DBC, BerkeleyRpmDbDeleter> m_cursor;
            bool m_firstIteration;

            std::vector<BerkeleyHeaderEntry> parseHeader(const DBT & data)
            {
                auto bytes { reinterpret_cast<uint8_t *>(data.data) };
                int32_t * ip;

                ip = reinterpret_cast<int32_t *>(data.data);
                const auto indexSize { *ip };

                std::vector<BerkeleyHeaderEntry> retVal(indexSize);

                bytes = &bytes[FIRST_ENTRY_OFFSET];

                // Read all indexes
                for (auto i = 0; i < indexSize; ++i)
                {
                    auto ucp { reinterpret_cast<int8_t *>(bytes) };

                    ip = reinterpret_cast<int32_t *>(ucp);
                    const auto tag { *ip };
                    ucp += sizeof(int32_t);

                    const auto it { TAG_NAMES.find(tag) };

                    if (TAG_NAMES.end() != it)
                    {
                        retVal[i].tag = it->second;

                        ip = reinterpret_cast<int32_t *>(ucp);
                        retVal[i].type = *ip;
                        ucp += sizeof(int32_t);

                        ip = reinterpret_cast<int32_t *>(ucp);
                        retVal[i].offset = *ip;
                        ucp += sizeof(int32_t);

                        ip = reinterpret_cast<int32_t *>(ucp);
                        retVal[i].count = *ip;
                        ucp += sizeof(int32_t);
                    }
                    bytes = &bytes[ENTRY_SIZE];
                }
                return retVal;
            }

            std::string parseBody(const std::vector<BerkeleyHeaderEntry> & header, const DBT & data)
            {
                std::string retVal;
                int32_t * ip;
                auto bytes { reinterpret_cast<char *>(data.data) + FIRST_ENTRY_OFFSET + (ENTRY_SIZE * header.size()) };
                constexpr auto INT32_TYPE {4};
                constexpr auto STRING_TYPE {6};
                constexpr auto STRING_VECTOR_TYPE {9};

                for (const auto & TAG : TAG_NAMES)
                {
                    const auto it
                    {
                        std::find_if(header.begin(),
                                    header.end(),
                                    [&TAG](const BerkeleyHeaderEntry & headerEntry)
                                    {
                                        return TAG.second.compare(headerEntry.tag) == 0;
                                    })
                    };

                    if (it != header.end())
                    {
                        auto ucp { &bytes[it->offset] };

                        if (STRING_TYPE == it->type)
                        {
                            retVal += ucp;
                        }
                        else if (INT32_TYPE == it->type)
                        {
                            ip = reinterpret_cast<int32_t *>(ucp);
                            retVal += *ip;
                        }
                        else if (STRING_VECTOR_TYPE == it->type)
                        {
                            retVal += ucp;
                        }
                    }
                    retVal += "\t";
                }
                retVal += "\n";

                return retVal;
            }

        public:
            std::string getNext()
            {
                std::string retVal;
                DBT key, data;
                std::memset(&key, 0, sizeof(DBT));
                std::memset(&data, 0, sizeof(DBT));
                int cursorRet;

                if(true == m_firstIteration)
                {
                    if (cursorRet = m_cursor->c_get(m_cursor.get(), &key, &data, DB_NEXT) == 0)
                    {
                        m_firstIteration = false;
                    }
                }

                if (cursorRet = m_cursor->c_get(m_cursor.get(), &key, &data, DB_NEXT) == 0)
                {
                    retVal = parseBody(parseHeader(data), data);
                }

                return retVal;
            }
            BerkeleyRpmDBWrapper()
                : m_firstIteration { true }
            {
                int ret;
                DB * dbp;
                DBC * cursor;

                if ((ret = db_create(&dbp, NULL, 0)) != 0)
                {
                    throw std::runtime_error { db_strerror(ret) };
                }

                m_db = std::unique_ptr<DB, BerkeleyRpmDbDeleter>(dbp);

                // Set Little-endian order by default
                if (ret = m_db->set_lorder(m_db.get(), 1234), ret != 0)
                {
                    //mtwarn(WM_SYS_LOGTAG, "Error setting byte-order.");
                }

                if ((ret = m_db->open(m_db.get(), NULL, RPM_DATABASE, NULL, DB_HASH, DB_RDONLY, 0)) != 0)
                {
                    throw std::runtime_error { std::string("Failed to open database '") + RPM_DATABASE + "': " + db_strerror(ret) };
                }

                if ((ret = m_db->cursor(m_db.get(), NULL, &cursor, 0)) != 0)
                {
                    throw std::runtime_error { std::string("Error creating cursor: ") + db_strerror(ret) };
                }
                m_cursor = std::unique_ptr<DBC, BerkeleyRpmDbDeleter>(cursor);
            }

            ~BerkeleyRpmDBWrapper() { }
    };
};
#endif // _BERKELEY_RPM_DB_HELPER_H