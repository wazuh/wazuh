/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * October 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMD_HELPER_H
#define _CMD_HELPER_H

#include <string>
#include <iostream>
#include <cstdio>
#include <memory>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils
{
    struct FileSmartDeleter
    {
        void operator()(FILE* file)
        {
            pclose(file);
        }
    };
    static std::string exec(const std::string& cmd, const size_t bufferSize = 128)
    {
        const std::unique_ptr<FILE, FileSmartDeleter> file{popen(cmd.c_str(), "r")};
        char buffer[bufferSize];
        std::string result;

        if (file)
        {
            while (fgets(buffer, bufferSize, file.get()))
            {
                result += buffer;
            }
        }

        return result;
    }
}

#pragma GCC diagnostic pop

#endif // _CMD_HELPER_H