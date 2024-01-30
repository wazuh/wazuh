/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * January 30, 2024.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _HOMEDIR_H
#define _HOMEDIR_H

#include <iostream>
#include <cstring>
#include <climits>
#include <cstdlib>
#include <sys/stat.h>
#include <libgen.h>


namespace Utils
{
    char* w_strtok_delim(const char* delim, char** remaining_str) {
        if (!*remaining_str) {
            return nullptr;
        }

        if (!delim || *delim == '\0') {
            char* str = *remaining_str;
            *remaining_str = nullptr;
            return str;
        }

        char* delim_found = nullptr;
        size_t delim_len = std::strlen(delim);

        while ((delim_found = std::strstr(*remaining_str, delim))) {
            if (*remaining_str == delim_found) {
                *remaining_str += delim_len;
                continue;
            }
            break;
        }

        if (**remaining_str == '\0') {
            return nullptr;
        }

        char* token = *remaining_str;

        if ((delim_found = std::strstr(*remaining_str, delim))) {
            *delim_found = '\0';
            *remaining_str = delim_found + delim_len;
        } else {
            *remaining_str = nullptr;
        }

        return token;
    }

    char* w_homedir(char* arg) {
        char* buff = nullptr;
        struct stat buff_stat;
        const char* delim = "/bin";
        
        buff = new char[PATH_MAX];

        if (realpath("/proc/self/exe", buff) || realpath("/proc/curproc/file", buff) ||
            realpath("/proc/self/path/a.out", buff) || (realpath(arg, buff) != nullptr)) {
            dirname(buff);
            buff = w_strtok_delim(delim, &buff);
        } else {
            // The path was not found, so read WAZUH_HOME env var
            char* home_env = nullptr;
            if ((home_env = getenv("WAZUH_HOME")) != nullptr) {
                std::snprintf(buff, PATH_MAX, "%s", home_env);
            }
        }

        if ((stat(buff, &buff_stat) < 0) || !S_ISDIR(buff_stat.st_mode)) {
            delete[] buff;
            std::cerr << "HOME_ERROR" << std::endl;
            std::exit(EXIT_FAILURE);
        }

        return buff;
    }
}

#endif // _HOMEDIR_H
