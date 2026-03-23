/*
 * Wazuh Vulnerability scanner - Scan Orchestrator
 * Copyright (C) 2015, Wazuh Inc.
 * Nov 23, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CERT_HELPER_HPP
#define _CERT_HELPER_HPP

#include <filesystem>
#include <fstream>
#include <grp.h>
#include <pwd.h>
#include <string>
#include <unistd.h>
#include <vector>

constexpr auto USER_GROUP {"wazuh"};

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-function"

namespace Utils::CertHelper
{
    static void mergeCaRootCertificates(const std::vector<std::string>& filePaths,
                                        std::string& caRootCertificate,
                                        std::string_view mergedCaRootCertificate)
    {
        std::string caRootCertificateContentMerged;

        for (const auto& filePath : filePaths)
        {
            if (!std::filesystem::exists(filePath))
            {
                throw std::runtime_error("The CA root certificate file: '" + filePath + "' does not exist.");
            }

            std::ifstream file(filePath);
            if (!file.is_open())
            {
                throw std::runtime_error("Could not open CA root certificate file: '" + filePath + "'.");
            }

            caRootCertificateContentMerged.append((std::istreambuf_iterator<char>(file)),
                                                  std::istreambuf_iterator<char>());
        }

        caRootCertificate = mergedCaRootCertificate;

        if (std::filesystem::path dirPath = std::filesystem::path(caRootCertificate).parent_path();
            !std::filesystem::exists(dirPath) && !std::filesystem::create_directories(dirPath))
        {
            throw std::runtime_error("Could not create the directory for the CA root merged file");
        }

        std::ofstream outputFile(caRootCertificate);
        if (!outputFile.is_open())
        {
            throw std::runtime_error("Could not write the CA root merged file");
        }

        outputFile << caRootCertificateContentMerged;
        outputFile.close();

        struct passwd const* pwd = getpwnam(USER_GROUP);
        struct group const* grp = getgrnam(USER_GROUP);

        if (pwd == nullptr || grp == nullptr)
        {
            throw std::runtime_error("Could not get the user and group information.");
        }

        if (chown(caRootCertificate.c_str(), pwd->pw_uid, grp->gr_gid) != 0)
        {
            throw std::runtime_error("Could not change the ownership of the CA root merged file");
        }
    }
} // namespace Utils::CertHelper

#pragma GCC diagnostic pop

#endif // _CERT_HELPER_HPP
