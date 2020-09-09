/*
 * Wazuh RSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * Sep 08, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CMD_LINE_ARGS_HELPER_H_
#define _CMD_LINE_ARGS_HELPER_H_

#include <string>
#include <sstream>
#include <vector>
#include <iostream>

class CmdLineArgs
{
public:
    CmdLineArgs(const int argc, const char* argv[])
    : m_outputFolder{ paramValueOf(argc, argv, "-o") }
    , m_updatePeriod{ std::stoul(paramValueOf(argc, argv, "-u")) }
    {}

    const unsigned long& period() const
    {
        return m_updatePeriod;
    }

    const std::string& outputFolder() const
    {
        return m_outputFolder;
    }    

    static void showHelp()
    {
        std::cout << "\nUsage: dbsync_test_tool <option(s)> SOURCES \n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-u DB_UPDATE_PERIOD\tSpecifies the database update period.\n"
                  << "\t-o OUTPUT_FOLDER\tSpecifies the output folder path where the data bases will be generated.\n"         
                  << "\nExample:"
                  << "\n\t./rsync_test_tool -u 1000 -o ./output\n"
                  << std::endl;
    }

private:

    static std::string paramValueOf(const int argc,
                                    const char* argv[],
                                    const std::string& switchValue)
    {
        for(int i = 1; i < argc; ++i)
        {
            const std::string currentValue{ argv[i] };
            if(currentValue == switchValue && i+1 < argc)
            {
                // Switch found
                return argv[i+1];
            }
        }
        throw std::runtime_error
        {
            "Switch value: "+ switchValue +" not found."
        };
    }

    const std::string m_outputFolder;
    const unsigned long m_updatePeriod;
};

#endif // _CMD_LINE_ARGS_HELPER_H_