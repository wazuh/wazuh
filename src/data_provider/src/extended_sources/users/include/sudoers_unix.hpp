/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

#include <string>

#include "json.hpp"

#include <ifilesystem_wrapper.hpp>

class SudoersProvider
{
    public:
        /// Constructor
        explicit SudoersProvider(std::string fileName, std::unique_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr);

        /// Default constructor
        SudoersProvider();

        nlohmann::json collect();

    private:
        void genSudoersFile(const std::string& fileName,
                            unsigned int level,
                            nlohmann::json& results);

        // #if !defined(FREEBSD)
        // const std::string kSudoFile = "/etc/sudoers";
        // #else
        // const std::string kSudoFile = "/usr/local/etc/sudoers";
        // #endif
        std::string m_sudoFile;
        std::unique_ptr<IFileSystemWrapper> m_fileSystemWrapper;
};
