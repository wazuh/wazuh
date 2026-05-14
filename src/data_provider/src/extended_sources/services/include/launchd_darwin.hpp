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
#include <vector>
#include <map>
#include "json.hpp"

/// @brief Structure to hold information about a launchd service.
struct LaunchdService
{
    std::string path;
    std::string name;
    std::string label;
    std::string runAtLoad;
    std::string keepAlive;
    std::string stdoutPath;
    std::string stderrPath;
    std::string inetdCompatibility;
    std::string startInterval;
    std::string program;
    std::string startOnMount;
    std::string onDemand;
    std::string disabled;
    std::string username;
    std::string groupname;
    std::string rootDirectory;
    std::string workingDirectory;
    std::string processType;
    std::string programArguments;
    std::string watchPaths;
    std::string queueDirectories;
};

/// @brief Class to collect launchd services information from macOS.
/// This class reads plist files from known launchd paths and extracts
/// service information, formatting it into a JSON object for easy consumption.
class LaunchdProvider
{
    public:
        /// @brief Default constructor.
        LaunchdProvider();

        /// @brief Collects launchd services information.
        /// @return A JSON object containing the collected launchd services information.
        nlohmann::json collect();

    private:
        /// @brief Standard launchd search paths.
        const std::vector<std::string> m_launchdSearchPaths =
        {
            "/System/Library/LaunchDaemons",
            "/Library/LaunchDaemons",
            "/System/Library/LaunchAgents",
            "/Library/LaunchAgents",
            "/Library/Apple/System/Library/LaunchDaemons",
            "/Library/Apple/System/Library/LaunchAgents",
        };

        /// @brief User-specific launchd search paths.
        const std::vector<std::string> m_userLaunchdSearchPaths =
        {
            "Library/LaunchAgents",
        };

        /// @brief Mapping of plist keys to service structure fields for string values.
        const std::map<std::string, std::string> m_launchdTopLevelStringKeys =
        {
            {"Label", "label"},
            {"RunAtLoad", "run_at_load"},
            {"KeepAlive", "keep_alive"},
            {"StandardOutPath", "stdout_path"},
            {"StandardErrorPath", "stderr_path"},
            {"inetdCompatibility", "inetd_compatibility"},
            {"StartInterval", "start_interval"},
            {"Program", "program"},
            {"StartOnMount", "start_on_mount"},
            {"OnDemand", "on_demand"},
            {"Disabled", "disabled"},
            {"UserName", "username"},
            {"GroupName", "groupname"},
            {"RootDirectory", "root_directory"},
            {"WorkingDirectory", "working_directory"},
            {"ProcessType", "process_type"},
        };

        /// @brief Mapping of plist keys to service structure fields for array values.
        const std::map<std::string, std::string> m_launchdTopLevelArrayKeys =
        {
            {"ProgramArguments", "program_arguments"},
            {"WatchPaths", "watch_paths"},
            {"QueueDirectories", "queue_directories"},
        };

        /// @brief Retrieves all launcher plist files from known paths.
        /// @param launchers Vector to store the found plist file paths.
        void getLauncherPaths(std::vector<std::string>& launchers);

        /// @brief Parses a plist file and extracts service information.
        /// @param path Path to the plist file.
        /// @param service LaunchdService structure to fill with parsed data.
        /// @return True if parsing was successful, false otherwise.
        bool parsePlistFile(const std::string& path, LaunchdService& service);

        /// @brief Joins array elements into a space-separated string.
        /// @param arrayElements Vector of strings to join.
        /// @return Joined string.
        std::string joinArrayElements(const std::vector<std::string>& arrayElements);
};
