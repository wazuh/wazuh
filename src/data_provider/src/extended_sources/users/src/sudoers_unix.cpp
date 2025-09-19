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

#include "filesystemHelper.h"
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

    if (!Utils::existsRegular(fileName))
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
            isLongLine = (!line.empty() && line.back() == '\\');
            auto& lastLine = results.back();

            // Remove trailing backslash from the line before appending
            std::string lineToAppend = line;

            if (!lineToAppend.empty() && lineToAppend.back() == '\\')
            {
                lineToAppend.pop_back();
                Utils::trimSpaces(lineToAppend);
            }

            lastLine["rule_details"] = lastLine["rule_details"].get<std::string>() + " " + lineToAppend;
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
        if (!line.empty() && line.at(0) == '#' && !isInclude && !isIncludeDir)
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
        if (!isInclude && !isIncludeDir && !line.empty() && line.back() == '\\')
        {
            isLongLine = true;

            // Remove trailing backslash from rule_details for consistency
            if (!ruleDetails.empty() && ruleDetails.back() == '\\')
            {
                ruleDetails.pop_back();
                Utils::trimSpaces(ruleDetails);
            }
        }

        nlohmann::json entry;
        entry["header"] = header;
        entry["source"] = fileName;
        entry["rule_details"] = ruleDetails;
        results.push_back(std::move(entry));

        if (isIncludeDir)
        {
            // support both relative and full paths
            if (!ruleDetails.empty() && ruleDetails.at(0) != '/')
            {
                ruleDetails = Utils::resolvePath(fileName, ruleDetails);
            }

            std::vector<std::string> inc_files = Utils::enumerateDir(ruleDetails);

            if (inc_files.empty())
            {
                // std::cout << "Could not list includedir: " << ruleDetails << std::endl;
                continue;
            }

            for (const auto& incFile : inc_files)
            {
                std::string incBasename = Utils::getFilename(incFile);

                // Per sudoers(5): Any files in the included directory that
                // contain a '.' or end with '~' are ignored.
                if (incBasename.empty() ||
                        incBasename.find('.') != std::string::npos ||
                        (!incBasename.empty() && incBasename.back() == '~'))
                {
                    continue;
                }

                genSudoersFile(incFile, level + 1, results);
            }
        }

        if (isInclude)
        {
            // Relative or full paths
            if (!ruleDetails.empty() && ruleDetails.at(0) != '/')
            {
                ruleDetails = Utils::resolvePath(fileName, ruleDetails);
            }

            genSudoersFile(ruleDetails, level + 1, results);
        }
    }
}
