/**
 * @file db_file_item.hpp
 * @brief
 * @date 2021-09-22
 *
 * @copyright Copyright (C) 2015-2021 Wazuh, Inc.
 */

#ifndef _DBFILEITEM_HPP
#define _DBFILEITEM_HPP
#include "shared.h"
#include "db_item.hpp"

class final File : public DBItem {
public:
    File();
    ~File();
    fim_entry* toFimEntry();
    nlohmann::json* toJSON();

private:
    int m_size;
    std::string m_perm;
    std::string m_attributes;
    int m_uid;
    std::string m_username;
    int m_gid;
    std::string m_groupname;
    time_t m_time;
    int m_inode;
    std::string m_md5;
    std::string m_sha1;
    std::string m_sha256;
    int m_dev;
    int m_options;
};
}
#endif //_DBFILEITEM_HPP