/*
 * Wazuh SysInfo
 * Copyright (C) 2015, Wazuh Inc.
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
        }

        void printProcessesInfo()
        {
            m_data["processes"] = m_sysinfo.processes();
        }

        void printPortsInfo()
        {
            m_data["ports"] = m_sysinfo.ports();
        }

        void printHotfixes()
        {
            m_data["hotfixes"] = m_sysinfo.hotfixes();
        }

        void printGroupsInfo()
        {
            m_data["groups"] = m_sysinfo.groups();
        }

        void printData()
        {
            std::cout << m_data.dump(JSON_PRETTY_SPACES) << std::endl;
        }

        void printProcessesInfoCallback()
        {
            m_sysinfo.processes([this](nlohmann::json & process)
            {
                m_data["processes_cb"].push_back(process);
            });
        }

        void printPackagesInfoCallback()
        {
            m_sysinfo.packages([this](nlohmann::json & package)
            {
                m_data["packages_cb"].push_back(package);
            });
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
            printer.printHotfixes();
            printer.printData();
            printer.printPackagesInfoCallback();
            printer.printProcessesInfoCallback();
        }
        else if (argc == 2)
        {
            CmdLineActions cmdLineArgs(argv);

            if (cmdLineArgs.hardwareArg())
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
            else if (cmdLineArgs.hotfixesArg())
            {
                printer.printHotfixes();
            }
            else if (cmdLineArgs.packagesCallbackArg())
            {
                printer.printPackagesInfoCallback();
            }
            else if (cmdLineArgs.processesCallbackArg())
            {
                printer.printProcessesInfoCallback();
            }
            else if (cmdLineArgs.groupsArg())
            {
                printer.printGroupsInfo();
            }
            else
            {
                throw std::runtime_error
                {
                    "Action value: " + std::string(argv[1]) + " not found."
                };
            }

            printer.printData();
        }
        else
        {
            throw std::runtime_error
            {
                "Multiple action are not allowed"
            };
        }
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error getting system information: " << e.what() << std::endl;
        CmdLineActions::showHelp();
    }
}
