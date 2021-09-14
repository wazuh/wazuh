/*
 * Wazuh SysInfo
 * Copyright (C) 2015-2021, Wazuh Inc.
 * February 25, 2021.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <iostream>
#include "cmdLineActions.h"
#include "sysInfo.hpp"
#include "sysInfo.h"

constexpr auto JSON_PRETTY_SPACES
{
    2
};

class SysInfoPrinter final
{
    public:
        SysInfoPrinter() = default;

        void printHardwareInfo()
        {
            m_data["hw"] = m_sysinfo.hardware();
        }

        void printNetworksInfo()
        {
            m_data["networks"] = m_sysinfo.networks();
        }

        void printOSInfo()
        {
            m_data["os"] = m_sysinfo.os();
        }

        void printPackagesInfo()
        {
            m_data["packages"] = m_sysinfo.packages();
            m_sysinfo.packages([](nlohmann::json& package)
            {
                std::cout << package.dump(JSON_PRETTY_SPACES) << std::endl;
            });
        }

        void printProcessesInfo()
        {
            m_data["processes"] = m_sysinfo.processes();
            m_sysinfo.processes([](nlohmann::json& process)
            {
                std::cout << process.dump(JSON_PRETTY_SPACES) << std::endl;
            });
        }

        void printPortsInfo()
        {
            m_data["ports"] = m_sysinfo.ports();
        }

        void printData()
        {
            std::cout << m_data.dump(JSON_PRETTY_SPACES) << std::endl;
        }

    private:
        SysInfo m_sysinfo;
        nlohmann::json m_data;
};

int main(int argc, const char* argv[])
{
    try
    {
        SysInfoPrinter printer;

        if (argc == 1)
        {
            // Calling testtool without parameters - default all
            printer.printHardwareInfo();
            printer.printNetworksInfo();
            printer.printOSInfo();
            printer.printPackagesInfo();
            printer.printProcessesInfo();
            printer.printPortsInfo();
            printer.printData();
        }
        else
        {
            CmdLineActions cmdLineArgs(argc, argv);
            if(cmdLineArgs.hardwareArg())
            {
                printer.printHardwareInfo();
            }
            else if (cmdLineArgs.networksArg())
            {
                printer.printNetworksInfo();
            }
            else if (cmdLineArgs.osArg())
            {
                printer.printOSInfo();
            }
            else if (cmdLineArgs.packagesArg())
            {
                printer.printPackagesInfo();
            }
            else if (cmdLineArgs.processesArg())
            {
                printer.printProcessesInfo();
            }
            else if (cmdLineArgs.portsArg())
            {
                printer.printPortsInfo();
            }
            printer.printData();
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error getting system information: " << e.what() << std::endl;
        CmdLineActions::showHelp();
    }
}
