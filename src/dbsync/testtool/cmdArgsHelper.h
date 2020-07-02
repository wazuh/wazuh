/*
 * Wazuh DBSYNC
 * Copyright (C) 2015-2020, Wazuh Inc.
 * June 11, 2020.
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
    CmdLineArgs(const int argc, char* argv[])
    {
        m_cmdLineArgs.reserve(argc);
        for (int i = 1; i < argc; ++i)
        {
            m_cmdLineArgs.push_back(argv[i]);
        }        
    }

    std::string configFile() const
    {
        return m_cmdLineArgs[ConfigValue];
    }

    void snapshotList(std::vector<std::string>& sList) const
    {
        std::stringstream ss{ m_cmdLineArgs[SnapshotsValue] }; 
        
        while (ss.good()) 
        { 
            std::string substr; 
            getline(ss, substr, ','); // Getting each string between ',' character 
            sList.push_back(substr); 
        } 
    }

    std::string outputFolder() const
    {
        return m_cmdLineArgs[OutputValue];
    }    

    void showHelp() const
    {
        std::cerr << "\nUsage: dbsync_test_tool <option(s)> SOURCES \n"
                  << "Options:\n"
                  << "\t-h \t\t\tShow this help message\n"
                  << "\t-c JSON_CONFIG_FILE\tSpecifies the json config file to initialize the database.\n"
                  << "\t-s SNAPSHOT_LIST\tSpecifies the list of snapshots to exercise the dabase.\n"
                  << "\t-o OUTPUT_FOLDER\tSpecifies the output folder path where the results will be generated.\n"         
                  << "\n Example:"
                  << "\n\t./dbsync_test_tool -c config.json -i input1.json,input2.json,input3.json -o ./output\n"
                  << std::endl;
    }

    bool argsAreOK() const
    {
        bool res{ false };
        if(m_cmdLineArgs.size() != 0)
        {
            const bool configOK
            { 
                m_cmdLineArgs[ConfigArg] == "-c" && !m_cmdLineArgs[ConfigValue].empty() 
            };
            const bool snapshotsOK
            { 
                m_cmdLineArgs[SnapshotsArg] == "-i" && !m_cmdLineArgs[SnapshotsValue].empty() 
            };
            const bool outputOK
            { 
                m_cmdLineArgs[OutputArg] == "-o" && !m_cmdLineArgs[OutputValue].empty()
            };
            res = configOK && snapshotsOK && outputOK;
        }
        return res;
    }
private:
    enum CmdLineValues
    {
        ConfigArg       = 0,    // -c arg
        ConfigValue     = 1,    // -c value
        SnapshotsArg    = 2,    // -i arg
        SnapshotsValue  = 3,    // -i value
        OutputArg       = 4,    // -o arg
        OutputValue     = 5     // -o value
    };

    CmdLineArgs() = delete;
    std::vector<std::string> m_cmdLineArgs;
};

#endif // _CMD_LINE_ARGS_HELPER_H_