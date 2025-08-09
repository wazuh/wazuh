/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <algorithm>
#include <sstream>
#include <iostream>
#include <regex>
#include <locale>
#include <vector>
#include <fstream>

#include <filesystem_wrapper.hpp>
#include <filesystem>

#include "stringHelper.h"

#include "sudoers_unix.hpp"

SudoersProvider::SudoersProvider(std::string fileName)
    : m_sudoFile(std::move(fileName))
{
}

SudoersProvider::SudoersProvider()
    : m_sudoFile("/etc/sudoers")
{
}

nlohmann::json SudoersProvider::collect()
{
    nlohmann::json results = nlohmann::json::array();

    genSudoersFile(m_sudoFile, 1, results);

    return results;
}


void SudoersProvider::genSudoersFile(const std::string& fileName,
                                     unsigned int level,
                                     nlohmann::json& results)
{
    // sudoers(5): No more than 128 files are allowed to be nested.
    static const unsigned int kMaxNest = 128;

    if (level > kMaxNest)
    {
        // std::cout << "sudoers file recursion maximum reached" << std::endl;
        return;
    }

    if (!std::filesystem::is_regular_file(fileName))
    {
        // std::cout << "sudoers file doesn't exists: " << fileName << std::endl;
        return;
    }

    std::ifstream file(fileName);

    if (!file.is_open())
    {
        // std::cout << "couldn't open sudoers file: " << fileName << std::endl;
        return;
    }

    bool isLongLine = false;
    auto contents = std::string((std::istreambuf_iterator<char>(file)),
                                std::istreambuf_iterator<char>());
    auto lines{Utils::split(contents, '\n')};

    for (auto& line : lines)
    {
        // sudoers uses EBNF for grammar.
        Utils::trimSpaces(line);

        if (line.empty())
        {
            continue;
        }

        // if last line contains a backslash as the last character, treat current line as part
        // of previous line and append it to appropriate column.
        if (isLongLine)
        {
            isLongLine = (line.back() == '\\');
            auto& lastLine = results.back();

            if (lastLine["rule_details"].empty())
            {
                if (lastLine["header"].empty())
                {
                    std::string tmp = lastLine["header"];
                    lastLine["header"] = tmp;
                }
            }
            else
            {
                if (lastLine["rule_details"].empty())
                {
                    std::string tmp = lastLine["rule_details"];
                    lastLine["rule_details"] = tmp;
                }
            }

            lastLine["rule_details"] = lastLine["rule_details"].get<std::string>() + line;
            continue;
        }


        // Find the rule header.
        auto headerLen = line.find_first_of("\t\v ");
        auto header = line.substr(0, headerLen);
        Utils::trimSpaces(header);

        // We frequently check if these are include headers. Do it once here.
        auto isInclude = (header == "#include" || header == "@include");
        auto isIncludeDir = (header == "#includedir" || header == "@includedir");

        // skip comments.
        if (line.at(0) == '#' && !isInclude && !isIncludeDir)
        {
            continue;
        }

        // Find the next field. Instead of skipping the whitespace, we
        // include it, and then trim it.
        auto ruleDetails = (headerLen < line.size()) ? line.substr(headerLen) : "";
        Utils::trimSpaces(ruleDetails);

        // If an include is _missing_ the target to include, treat it like a comment.
        if (ruleDetails.empty() && (isInclude || isIncludeDir))
        {
            continue;
        }

        // Check if a blackslash is the last character on this line.
        if (!isInclude && !isIncludeDir && line.back() == '\\')
        {
            isLongLine = true;
        }

        nlohmann::json entry;
        entry["header"] = header;
        entry["source"] = fileName;
        entry["rule_details"] = ruleDetails;
        results.push_back(std::move(entry));

        if (isIncludeDir)
        {
            // support both relative and full paths
            if (ruleDetails.at(0) != '/')
            {
                const auto fullPath = (std::filesystem::path(fileName).parent_path() / ruleDetails).string();
                ruleDetails = fullPath;
            }

            std::vector<std::filesystem::path> inc_files;

            try
            {
                inc_files = file_system::FileSystemWrapper().list_directory(ruleDetails);
            }
            catch (const std::filesystem::filesystem_error&)
            {
                // Directory doesn't exist or cannot be accessed, skip it
                // std::cout << "Could not list includedir: " << ruleDetails << std::endl;
                continue;
            }

            if (inc_files.empty())
            {
                // std::cout << "Could not list includedir: " << ruleDetails << std::endl;
                continue;
            }

            for (const auto& incFile : inc_files)
            {
                const auto incBasename = incFile.filename().string();

                // Per sudoers(5): Any files in the included directory that
                // contain a '.' or end with '~' are ignored.
                if (incBasename.empty() ||
                        incBasename.find('.') != std::string::npos ||
                        incBasename.back() == '~')
                {
                    continue;
                }

                genSudoersFile(incFile.string(), level + 1, results);
            }
        }

        if (isInclude)
        {
            // Relative or full paths
            if (ruleDetails.at(0) != '/')
            {
                const auto fullPath = (std::filesystem::path(fileName).parent_path() / ruleDetails).string();
                ruleDetails = fullPath;
            }

            genSudoersFile(ruleDetails, level + 1, results);
        }
    }
}
