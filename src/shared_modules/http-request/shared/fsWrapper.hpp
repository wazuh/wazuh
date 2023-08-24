/*
 * Wazuh shared modules utils
 * Copyright (C) 2015, Wazuh Inc.
 * Jul 10, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FSWRAPPER_HPP
#define _FSWRAPPER_HPP

#include <filesystem>

/**
 * @brief This class is a wrapper for the filesystem library.
 */
class FsWrapper
{
protected:
    FsWrapper() = default;
    virtual ~FsWrapper() = default;

public:
    /**
     * @brief Method to check if a file exists.
     * @param name The file name.
     */
    static bool exists(const std::string& name)
    {
        return std::filesystem::exists(name);
    }
};

#endif /* _FSWRAPPER_HPP */
