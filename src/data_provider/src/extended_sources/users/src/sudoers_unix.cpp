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
#include <filesystem>
#include <fstream>

#include "stringHelper.h"

#include "sudoers_unix.hpp"

SudoersProvider::SudoersProvider(const std::string fileName)
    : m_sudoFile(fileName)
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

    // Local utility functions/lambdas
    auto trim = [](std::string & s)
    {
        s.erase(s.begin(), std::find_if(s.begin(), s.end(), [](int ch)
        {
            return !std::isspace(ch);
        }));
        s.erase(std::find_if(s.rbegin(), s.rend(), [](int ch)
        {
            return !std::isspace(ch);
        }).base(), s.end());
    };

    auto listFilesInDirectory = [](const std::string & path, std::vector<std::string>& out)
    {
        try
        {
            for (const auto& entry : std::filesystem::directory_iterator(path))
            {
                if (entry.is_regular_file())
                {
                    out.push_back(entry.path().string());
                }
            }

            return true;
        }
        catch (...)
        {
            return false;
        }
    };

    if (level > kMaxNest)
    {
        // std::cout << "sudoers file recursion maximum reached" << std::endl;
        return;
    }

    if (!std::filesystem::exists(fileName) || !std::filesystem::is_regular_file(fileName))
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
        trim(line);

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
        trim(header);

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
        trim(ruleDetails);

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

        auto resolvePath = [&](const std::string & relativePath)
        {
            return (std::filesystem::path(fileName).parent_path() / relativePath).string();
        };

        if (isIncludeDir)
        {
            // support both relative and full paths
            if (ruleDetails.at(0) != '/')
            {
                ruleDetails = resolvePath(ruleDetails);
            }

            std::vector<std::string> inc_files;

            if (!listFilesInDirectory(ruleDetails, inc_files))
            {
                // std::cout << "Could not list includedir: " << ruleDetails << std::endl;
                continue;
            }

            for (const auto& incFile : inc_files)
            {
                std::string incBasename = std::filesystem::path(incFile).filename().string();

                // Per sudoers(5): Any files in the included directory that
                // contain a '.' or end with '~' are ignored.
                if (incBasename.empty() ||
                        incBasename.find('.') != std::string::npos ||
                        incBasename.back() == '~')
                {
                    continue;
                }

                genSudoersFile(incFile, ++level, results);
            }
        }

        if (isInclude)
        {
            // Relative or full paths
            if (ruleDetails.at(0) != '/')
            {
                ruleDetails = resolvePath(ruleDetails);
            }

            genSudoersFile(ruleDetails, ++level, results);
        }
    }
}
