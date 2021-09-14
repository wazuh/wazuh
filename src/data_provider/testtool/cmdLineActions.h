/*
 * Wazuh SYSINFO
 * Copyright (C) 2015-2021, Wazuh Inc.
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

class CmdLineActions final
{
    public:
        CmdLineActions(const int argc, const char* argv[])
            : m_hardware  { false }
            , m_networks  { false }
            , m_packages  { false }
            , m_processes { false }
            , m_ports     { false }
            , m_os        { false }
        {
            const auto cmdArg { argv[1] };
            if (argc == 2)
            {
                if (strncmp(cmdArg, "--hardware", 10) == 0)
                {
                    m_hardware = true;
                }
                else if (strncmp(cmdArg, "--networks", 10) == 0)
                {
                    m_networks = true;
                }
                else if (strncmp(cmdArg, "--packages", 10) == 0)
                {
                    m_packages = true;
                }
                else if (strncmp(cmdArg, "--processes", 11) == 0)
                {
                    m_processes = true;
                }
                else if (strncmp(cmdArg, "--ports", 7) == 0)
                {
                    m_ports = true;
                }
                else if (strncmp(cmdArg, "--os", 4) == 0)
                {
                    m_os = true;
                }
                else
                {
                    throw std::runtime_error
                    {
                        "Action value: " + std::string(cmdArg) + " not found."
                    };
                }
            }
            else
            {
                throw std::runtime_error
                {
                    "Multiple action are not allowed"
                };
            }
        }

        bool hardwareArg()
        {
            return m_hardware;
        };

        bool networksArg()
        {
            return m_networks;
        };

        bool packagesArg()
        {
            return m_packages;
        };

        bool processesArg()
        {
            return m_processes;
        };

        bool portsArg()
        {
            return m_ports;
        };

        bool osArg()
        {
            return m_os;
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
                      << "\t--ports \tPrints the current Operating System ports information.\n"
                      << "\t--os \t\tPrints the current Operating System information.\n"
                      << "\nExamples:"
                      << "\n\t./sysinfo_test_tool"
                      << "\n\t./sysinfo_test_tool --hardware"
                      << "\n\t./sysinfo_test_tool --networks"
                      << "\n\t./sysinfo_test_tool --packages"
                      << "\n\t./sysinfo_test_tool --processes"
                      << "\n\t./sysinfo_test_tool --ports"
                      << "\n\t./sysinfo_test_tool --os"
                      << std::endl;
        }

    private:
        bool m_hardware;
        bool m_networks;
        bool m_packages;
        bool m_processes;
        bool m_ports;
        bool m_os;
};

#endif // _CMD_LINE_ACTIONS_H_