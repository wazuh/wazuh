/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * July 14, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _JSONIO_HPP
#define _JSONIO_HPP

#include <filesystem>
#include <fstream>

/**
 * Class to read and write json files
 */
template<typename T>
class JsonIO
{
public:
    /**
     * Read a json file
     * @param filePath Path to the json file
     * @return Json object
     */
    static T readJson(const std::filesystem::path& filePath)
    {
        std::ifstream file(filePath);

        if (!file.is_open())
        {
            throw std::runtime_error("Could not open file");
        }

        T json;
        file >> json;
        return json;
    }

    /**
     * Write a json file
     * @param filePath Path to the json file
     * @param json Json object
     */
    static void writeJson(const std::filesystem::path& filePath, const T& json)
    {
        std::ofstream file(filePath);

        if (!file.is_open())
        {
            throw std::runtime_error("Could not open file");
        }

        file << json;

        if (!file.good())
        {
            throw std::runtime_error("Could not write file");
        }
    }
};

#endif
