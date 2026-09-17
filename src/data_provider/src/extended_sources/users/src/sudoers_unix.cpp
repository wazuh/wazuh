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
#include <map>
#include <regex>
#include <locale>
#include <utility>
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

                // enumerateDir() returns bare basenames; join with the includedir or
                // drop-ins resolve against the process CWD instead of it and are never read.
                std::string incFullPath = ruleDetails;

                if (!incFullPath.empty() && incFullPath.back() != '/')
                {
                    incFullPath += '/';
                }

                incFullPath += incBasename;

                genSudoersFile(incFullPath, level + 1, results);
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

namespace
{
    // Caps User_Alias indirection, which also stops aliases defined in terms of each other from
    // looping forever.
    constexpr unsigned int MAX_ALIAS_DEPTH = 16;

    bool isDirectiveHeader(const std::string& header)
    {
        static const std::set<std::string> DIRECTIVE_HEADERS
        {
            "User_Alias", "Runas_Alias", "Host_Alias", "Cmnd_Alias",
            "#include", "@include", "#includedir", "@includedir"
        };

        // "Defaults" also takes the qualified forms Defaults@host, Defaults:user, Defaults!cmnd
        // and Defaults>runas, none of which grant anything either.
        return DIRECTIVE_HEADERS.count(header) > 0 || header.rfind("Defaults", 0) == 0;
    }

    // A ':' separates alias definitions on one line, unless it follows a '%', which opens a
    // non-Unix group name ("%:group").
    std::vector<std::string> splitAliasDefinitions(const std::string& ruleDetails)
    {
        std::vector<std::string> definitions;
        std::string current;

        for (size_t i = 0; i < ruleDetails.size(); ++i)
        {
            if (ruleDetails[i] == ':' && (i == 0 || ruleDetails[i - 1] != '%'))
            {
                definitions.push_back(current);
                current.clear();
            }
            else
            {
                current.push_back(ruleDetails[i]);
            }
        }

        definitions.push_back(current);

        return definitions;
    }

    // genSudoersFile() cuts the header at the first whitespace token, so a user list written with
    // spaces after its commas continues at the start of the body. A trailing comma says the list
    // goes on, and the first entry without one closes it.
    std::string ruleUserList(const std::string& header, const std::string& ruleDetails)
    {
        std::string userList = header;
        size_t position = 0;

        while (!userList.empty() && userList.back() == ',')
        {
            const auto start = ruleDetails.find_first_not_of("\t\v ", position);

            if (start == std::string::npos)
            {
                break;
            }

            const auto end = ruleDetails.find_first_of("\t\v ", start);
            userList += ruleDetails.substr(start, end == std::string::npos ? std::string::npos : end - start);
            position = (end == std::string::npos) ? ruleDetails.size() : end;
        }

        return userList;
    }

    // Tracks the running result of evaluating a user list left-to-right, per sudoers(5): the last
    // entry that actually applies to the user wins, whether it grants or (via a "!"-prefixed entry)
    // revokes a grant an earlier entry in the same list gave.
    enum class ListMatchState
    {
        NoMatch,
        Granted,
        Denied
    };

    bool userListGrants(const std::string& userList,
                        const std::string& userName,
                        const std::set<std::string>& userGroups,
                        const std::map<std::string, std::string>& userAliases,
                        unsigned int depth);

    // Strips any leading "!" characters from a user-list entry and reports whether their count is
    // odd, i.e. whether the entry is actually negated ("!!user" cancels out back to "user").
    std::pair<bool, std::string> stripNegation(const std::string& entry)
    {
        size_t i = 0;

        while (i < entry.size() && entry[i] == '!')
        {
            ++i;
        }

        return {(i % 2) == 1, entry.substr(i)};
    }

    // Answers whether an entry's underlying condition (ignoring any "!" prefix, already stripped by
    // the caller) matches the user -- the caller decides whether that grants or denies.
    bool entryMatches(const std::string& entry,
                      const std::string& userName,
                      const std::set<std::string>& userGroups,
                      const std::map<std::string, std::string>& userAliases,
                      unsigned int depth)
    {
        // A netgroup cannot be resolved from the endpoint, so it can never be read as "this user is
        // a sudoer".
        if (entry.empty() || entry.front() == '+')
        {
            return false;
        }

        // "ALL" as the user list of a rule grants that rule to every account on the host.
        if (entry == "ALL")
        {
            return true;
        }

        if (entry.front() == '%')
        {
            auto groupName = entry.substr(1);

            // "%#gid" names a group by id, which group names cannot answer.
            if (!groupName.empty() && groupName.front() == '#')
            {
                return false;
            }

            // "%:group" names a non-Unix group; the name after the colon is the one that shows up
            // among the user's groups.
            if (!groupName.empty() && groupName.front() == ':')
            {
                groupName.erase(0, 1);
            }

            return userGroups.count(groupName) > 0;
        }

        // "#uid" names a user by id, which a name cannot answer.
        if (entry.front() == '#')
        {
            return false;
        }

        const auto alias = userAliases.find(entry);

        if (alias != userAliases.end())
        {
            return depth < MAX_ALIAS_DEPTH
                   && userListGrants(alias->second, userName, userGroups, userAliases, depth + 1);
        }

        return entry == userName;
    }

    ListMatchState userListMatchState(const std::string& userList,
                                      const std::string& userName,
                                      const std::set<std::string>& userGroups,
                                      const std::map<std::string, std::string>& userAliases,
                                      unsigned int depth)
    {
        ListMatchState state = ListMatchState::NoMatch;

        for (auto& rawEntry : Utils::split(userList, ','))
        {
            Utils::trimSpaces(rawEntry);

            const auto [negated, entry] = stripNegation(rawEntry);

            // A bare "!" (or an even run of them reducing to nothing) has no underlying condition to
            // test, so it never matches and leaves the running result untouched.
            if (entry.empty())
            {
                continue;
            }

            if (entryMatches(entry, userName, userGroups, userAliases, depth))
            {
                state = negated ? ListMatchState::Denied : ListMatchState::Granted;
            }
        }

        return state;
    }

    // Whether a user list grants sudo to the user, once negation within it has been resolved via
    // last-match-wins.
    bool userListGrants(const std::string& userList,
                        const std::string& userName,
                        const std::set<std::string>& userGroups,
                        const std::map<std::string, std::string>& userAliases,
                        unsigned int depth)
    {
        return userListMatchState(userList, userName, userGroups, userAliases, depth) == ListMatchState::Granted;
    }
}

std::map<std::string, std::string> SudoersProvider::collectUserAliases(const nlohmann::json& sudoers)
{
    std::map<std::string, std::string> aliases;

    for (const auto& rule : sudoers)
    {
        if (!rule.is_object() || rule.value("header", "") != "User_Alias")
        {
            continue;
        }

        for (const auto& definition : splitAliasDefinitions(rule.value("rule_details", "")))
        {
            const auto separator = definition.find('=');

            if (separator == std::string::npos)
            {
                continue;
            }

            auto name = definition.substr(0, separator);
            auto members = definition.substr(separator + 1);
            Utils::trimSpaces(name);
            Utils::trimSpaces(members);

            if (!name.empty())
            {
                aliases[name] = members;
            }
        }
    }

    return aliases;
}

bool SudoersProvider::isUserSudoer(const nlohmann::json& sudoers,
                                   const std::string& userName,
                                   const std::set<std::string>& userGroups)
{
    return isUserSudoer(sudoers, userName, userGroups, collectUserAliases(sudoers));
}

bool SudoersProvider::isUserSudoer(const nlohmann::json& sudoers,
                                   const std::string& userName,
                                   const std::set<std::string>& userGroups,
                                   const std::map<std::string, std::string>& userAliases)
{
    if (userName.empty() || !sudoers.is_array())
    {
        return false;
    }

    // sudoers(5) precedence is last-match-wins across the whole policy, not just within one
    // rule's user list, so `state` must persist across rules the same way userListMatchState()
    // already persists it across one list's entries.
    ListMatchState state = ListMatchState::NoMatch;

    for (const auto& rule : sudoers)
    {
        if (!rule.is_object())
        {
            continue;
        }

        const auto header = rule.value("header", "");

        if (isDirectiveHeader(header))
        {
            continue;
        }

        const auto userList = ruleUserList(header, rule.value("rule_details", ""));
        const auto ruleState = userListMatchState(userList, userName, userGroups, userAliases, 0);

        if (ruleState != ListMatchState::NoMatch)
        {
            state = ruleState;
        }
    }

    return state == ListMatchState::Granted;
}
