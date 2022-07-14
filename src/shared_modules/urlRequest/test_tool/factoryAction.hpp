/*
 * Wazuh urlRequest TestTool
 * Copyright (C) 2015, Wazuh Inc.
 * July 13, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _FACTORY_ACTION_HPP
#define _FACTORY_ACTION_HPP

#include <iostream>
#include <memory>
#include "actions.hpp"
#include "cmdArgsParser.hpp"

class FactoryAction final
{
    public:
        static std::unique_ptr<IAction> create(const CmdLineArgs& args)
        {
            if (0 == args.type().compare("download"))
            {
                return std::make_unique<DownloadAction>(args.url(), args.outputFile());
            }
            else if (0 == args.type().compare("get"))
            {
                return std::make_unique<GetAction>(args.url());
            }
            else if (0 == args.type().compare("post"))
            {
                return std::make_unique<PostAction>(args.url(), args.postArguments());
            }
            else if (0 == args.type().compare("put"))
            {
                return std::make_unique<PutAction>(args.url(), args.postArguments());
            }
            else if (0 == args.type().compare("delete"))
            {
                return std::make_unique<DeleteAction>(args.url());
            }
            else
            {
                throw std::runtime_error("Unknown action type");
            }
            return {};
        }
};

#endif // _FACTORY_ACTION_HPP
