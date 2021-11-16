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

#ifndef _FIMDBHELPER_HPP
#define _FIMDBHELPER_HPP
#include "fimDB.hpp"
#include "dbItem.hpp"

namespace FIMDBHelper
{
    /**
    * @brief Insert a new row from a table.
    *
    * @param tableName a string with the table name
    * @param item a RegistryKey, RegistryValue or File with their parameters
    *
    * @return 0 on success, another value otherwise.
    */
    int insertItem(const std::string &, const nlohmann::json &);

    /**
    * @brief Get count of all entries in a table
    *
    * @param tableName a string with the table name
    *
    * @return amount of entries on success, 0 otherwise.
    */
    int getCount(const std::string &);

    /**
    * @brief Get a item from a query
    *
    * @param item a item object where will be saved the query information
    * @param query a json with a query to the database
    *
    * @return a file, registryKey or registryValue, nullptr otherwise.
    */
    int getDBItem(DBItem &, const nlohmann::json &);

    /**
    * @brief Delete a row from a table
    *
    * @param tableName a string with the table name
    * @param query a json with a filter to delete an element to the database
    *
    * @return 0 on success, another value otherwise.
    */
    int removeFromDB(const std::string &, const nlohmann::json &);

    /**
    * @brief Update a row from a table.
    *
    * @param tableName a string with the table name
    * @param item a RegistryKey, RegistryValue or File with their parameters
    *
    * @return 0 on success, another value otherwise.
    */
    int updateItem(const std::string &, const nlohmann::json &);
}

#endif //_FIMDBHELPER_H
