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
#include <string>
#include <unistd.h>
#include <vector>

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

        // The account running this process, not a fixed name: the 5.x manager package creates
        // 'wazuh-manager' and removes 'wazuh', which the agent package creates. Either literal is
        // wrong on the other side, loudly on a manager and silently on a host with both.
        if (chown(caRootCertificate.c_str(), geteuid(), getegid()) != 0)
        {
            throw std::runtime_error("Could not change the ownership of the CA root merged file to " +
                                     std::to_string(geteuid()) + ":" + std::to_string(getegid()));
        }
    }
} // namespace Utils::CertHelper

#pragma GCC diagnostic pop

#endif // _CERT_HELPER_HPP
