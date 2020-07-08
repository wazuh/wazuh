/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * July 02, 2020.
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
    : m_configFile{ paramValueOf(argc, argv, "-c") }
    , m_outputFolder{ paramValueOf(argc, argv, "-o") }
    , m_snapshots{ splitSnapshots(paramValueOf(argc, argv, "-s")) }
    {}

    const std::string& configFile() const
    {
        return m_configFile;
    }

    const std::vector<std::string>& snapshots() const
    {
        return m_snapshots;
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
                  << "\t-c JSON_CONFIG_FILE\tSpecifies the json config file to initialize the database.\n"
                  << "\t-s SNAPSHOT_LIST\tSpecifies the list of snapshots to exercise the dabase.\n"
                  << "\t-o OUTPUT_FOLDER\tSpecifies the output folder path where the results will be generated.\n"         
                  << "\nExample:"
                  << "\n\t./dbsync_test_tool -c config.json -s input1.json,input2.json,input3.json -o ./output\n"
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

    static std::vector<std::string> splitSnapshots(const std::string& values)
    {
        std::vector<std::string> snapshots;
        std::stringstream ss{ values };
        while (ss.good())
        {
            std::string substr;
            getline(ss, substr, ','); // Getting each string between ',' character
            snapshots.push_back(std::move(substr));
        }
        return snapshots;
    }

    const std::string m_configFile;
    const std::string m_outputFolder;
    const std::vector<std::string> m_snapshots;
};

#endif // _CMD_LINE_ARGS_HELPER_H_