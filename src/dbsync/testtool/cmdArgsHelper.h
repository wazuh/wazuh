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
    {
        m_cmdLineArgs.reserve(argc);
        for (int i = 1; i < argc; ++i)
        {
            m_cmdLineArgs.push_back(argv[i]);
        }
    }

    const std::string configFile() const
    {
        return std::move(paramValueOf("-c"));
    }

    void snapshotList(std::vector<std::string>& snapshots) const
    {
        std::stringstream ss{ std::move(paramValueOf("-s")) };
        while (ss.good()) 
        { 
            std::string substr; 
            getline(ss, substr, ','); // Getting each string between ',' character 
            snapshots.push_back(std::move(substr));
        } 
    }

    const std::string outputFolder() const
    {
        return std::move(paramValueOf("-o"));
    }    

    void showHelp() const
    {
        std::cout << "\nUsage: dbsync_test_tool <option(s)> SOURCES \n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-c JSON_CONFIG_FILE\tSpecifies the json config file to initialize the database.\n"
                  << "\t-s SNAPSHOT_LIST\tSpecifies the list of snapshots to exercise the dabase.\n"
                  << "\t-o OUTPUT_FOLDER\tSpecifies the output folder path where the results will be generated.\n"         
                  << "\n Example:"
                  << "\n\t./dbsync_test_tool -c config.json -s input1.json,input2.json,input3.json -o ./output\n"
                  << std::endl;
    }

    bool argsAreOK() const
    {
        bool res{ false };
        if(m_cmdLineArgs.size() != 0)
        {
            bool configOK{ false };
            bool snapshotsOK{ false };
            bool outputOK{ false };
            const auto argsSize{ m_cmdLineArgs.size() };
            for(size_t i = 0ull; i < argsSize; ++i)
            {
                if(m_cmdLineArgs[i].compare("-c") == 0 && (i+1 < argsSize) && !m_cmdLineArgs[i+1].empty())
                {
                    configOK = true;
                }
                else if(m_cmdLineArgs[i].compare("-s") == 0 && (i+1 < argsSize) && !m_cmdLineArgs[i+1].empty())
                {
                    snapshotsOK = true;
                }
                else if(m_cmdLineArgs[i].compare("-o") == 0 && (i+1 < argsSize) && !m_cmdLineArgs[i+1].empty())
                {
                    outputOK = true;
                }
            }
            res = configOK && snapshotsOK && outputOK;
        }
        return res;
    }
private:

    const std::string paramValueOf(const std::string& input) const
    {
        std::string result;
        const auto argsSize{ m_cmdLineArgs.size() };
        for(unsigned int i = 0; i < argsSize; ++i)
        {
            if(m_cmdLineArgs[i].compare(input) == 0 && (i+1 < argsSize) && !m_cmdLineArgs[i+1].empty())
            {
                result = m_cmdLineArgs[i+1];
                break;
            }
        }
        return std::move(result);
    }

    std::vector<std::string> m_cmdLineArgs;
};

#endif // _CMD_LINE_ARGS_HELPER_H_