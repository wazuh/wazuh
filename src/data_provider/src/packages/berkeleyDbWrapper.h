/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * March 16, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _BERKELEY_DB_WRAPPER_H
#define _BERKELEY_DB_WRAPPER_H

#include "iberkeleyDbWrapper.h"

struct BerkeleyRpmDbDeleter final
{
    void operator()(DB* db)
    {
        db->close(db, 0);
    }
    void operator()(DBC* cursor)
    {
        cursor->c_close(cursor);
    }
};

class BerkeleyDbWrapper final : public IBerkeleyDbWrapper
{
    private:
        std::unique_ptr<DB, BerkeleyRpmDbDeleter>  m_db;
        std::unique_ptr<DBC, BerkeleyRpmDbDeleter> m_cursor;
    public:
        int32_t getRow(DBT& key, DBT& data) override
        {
            std::memset(&key, 0, sizeof(DBT));
            std::memset(&data, 0, sizeof(DBT));
            return m_cursor->c_get(m_cursor.get(), &key, &data, DB_NEXT);
        }
        // LCOV_EXCL_START
        ~BerkeleyDbWrapper() = default;
        // LCOV_EXCL_STOP
        explicit BerkeleyDbWrapper(const std::string& directory)
        {
            int ret;
            DB* dbp;
            DBC* cursor;

            if ((ret = db_create(&dbp, NULL, 0)) != 0)
            {
                throw std::runtime_error { db_strerror(ret) };
            }

            m_db = std::unique_ptr<DB, BerkeleyRpmDbDeleter>(dbp);

            // Set Big-endian order by default
            m_db->set_lorder(m_db.get(), 1234);

            if ((ret = m_db->open(m_db.get(), NULL, directory.c_str(), NULL, DB_HASH, DB_RDONLY, 0)) != 0)
            {
                throw std::runtime_error { std::string("Failed to open database '") + directory + "': " + db_strerror(ret) };
            }

            if ((ret = m_db->cursor(m_db.get(), NULL, &cursor, 0)) != 0)
            {
                throw std::runtime_error { std::string("Error creating cursor: ") + db_strerror(ret) };
            }

            m_cursor = std::unique_ptr<DBC, BerkeleyRpmDbDeleter>(cursor);
        }
};

#endif // _BERKELEY_DB_WRAPPER_H
