/*
 * Wazuh SYSINFO
 * Copyright (C) 2015, Wazuh Inc.
 * September 13, 2021
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMD_LINE_ACTIONS_H_
#define _CMD_LINE_ACTIONS_H_

#include <string.h>

constexpr auto HARDWARE_ACTION     { "--hardware"};
constexpr auto NETWORKS_ACTION     { "--networks"};
constexpr auto PACKAGES_ACTION     { "--packages"};
constexpr auto PROCESSES_ACTION    { "--processes"};
constexpr auto PORTS_ACTION        { "--ports"};
constexpr auto OS_ACTION           { "--os"};
constexpr auto HOTFIXES_ACTION     { "--hotfixes"};
constexpr auto PROCESSES_CB_ACTION { "--processes-cb"};
constexpr auto PACKAGES_CB_ACTION  { "--packages-cb"};
constexpr auto GROUPS_ACTION       { "--groups" };

class CmdLineActions final
{
    public:
        CmdLineActions(const char* argv[])
            : m_hardware          { HARDWARE_ACTION     == std::string(argv[1]) }
            , m_networks          { NETWORKS_ACTION     == std::string(argv[1]) }
            , m_packages          { PACKAGES_ACTION     == std::string(argv[1]) }
            , m_processes         { PROCESSES_ACTION    == std::string(argv[1]) }
            , m_ports             { PORTS_ACTION        == std::string(argv[1]) }
            , m_os                { OS_ACTION           == std::string(argv[1]) }
            , m_hotfixes          { HOTFIXES_ACTION     == std::string(argv[1]) }
            , m_processesCallback { PROCESSES_CB_ACTION == std::string(argv[1]) }
            , m_packagesCallback  { PACKAGES_CB_ACTION  == std::string(argv[1]) }
            , m_groups            { GROUPS_ACTION       == std::string(argv[1]) }

        {}

        bool hardwareArg() const
        {
            return m_hardware;
        };

        bool networksArg() const
        {
            return m_networks;
        };

        bool packagesArg() const
        {
            return m_packages;
        };

        bool processesArg() const
        {
            return m_processes;
        };

        bool portsArg() const
        {
            return m_ports;
        };

        bool osArg() const
        {
            return m_os;
        };

        bool hotfixesArg() const
        {
            return m_hotfixes;
        };

        bool packagesCallbackArg() const
        {
            return m_packagesCallback;
        };

        bool processesCallbackArg() const
        {
            return m_processesCallback;
        };

        bool groupsArg() const
        {
            return m_groups;
        };

        static void showHelp()
        {
            std::cout << "\nUsage: sysinfo_test_tool [options]\n"
                      << "Options:\n"
                      << "\t<without args> \tPrints the complete Operating System information.\n"
                      << "\t--hardware \tPrints the current Operating System hardware information.\n"
                      << "\t--networks \tPrints the current Operating System networks information.\n"
                      << "\t--packages \tPrints the current Operating System packages information.\n"
                      << "\t--processes \tPrints the current Operating System processes information.\n"
                      << "\t--packages-cb \tPrints the current Operating System packages using callbacks to return information.\n"
                      << "\t--processes-cb \tPrints the current Operating System processes using callback to return information.\n"
                      << "\t--ports \tPrints the current Operating System ports information.\n"
                      << "\t--os \t\tPrints the current Operating System information.\n"
                      << "\t--hotfixes \tPrints the current Operating System hotfixes information.\n"
                      << "\t--groups \tPrints the current Operating System groups information.\n"
                      << "\nExamples:"
                      << "\n\t./sysinfo_test_tool"
                      << "\n\t./sysinfo_test_tool --hardware"
                      << "\n\t./sysinfo_test_tool --networks"
                      << "\n\t./sysinfo_test_tool --packages"
                      << "\n\t./sysinfo_test_tool --processes"
                      << "\n\t./sysinfo_test_tool --ports"
                      << "\n\t./sysinfo_test_tool --os"
                      << "\n\t./sysinfo_test_tool --hotfixes"
                      << "\n\t./sysinfo_test_tool --processes-cb"
                      << "\n\t./sysinfo_test_tool --packages-cb"
                      << "\n\t./sysinfo_test_tool --groups"
                      << std::endl;
        }

    private:
        const bool m_hardware;
        const bool m_networks;
        const bool m_packages;
        const bool m_processes;
        const bool m_ports;
        const bool m_os;
        const bool m_hotfixes;
        const bool m_processesCallback;
        const bool m_packagesCallback;
        const bool m_groups;

};

#endif // _CMD_LINE_ACTIONS_H_
