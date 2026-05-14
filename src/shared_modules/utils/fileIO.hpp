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

#ifndef _FILEIO_HPP
#define _FILEIO_HPP

#include <filesystem>
#include <fstream>
#include <functional>

/**
 * Class to read file contents
 */
class FileIO
{
    public:
        static void readLineByLine(
            const std::filesystem::path& filePath,
            const std::function<bool(const std::string&)>& callback)
        {
            std::ifstream file(filePath);

            if (!file.is_open())
            {
                throw std::runtime_error("Could not open file");
            }

            std::string line;

            while (std::getline(file, line))
            {
                if (!callback(line))
                {
                    break;
                }
            }
        }
};

#endif  // _FILEIO_HPP
