/*
 * Wazuh FIMDB
 * Copyright (C) 2015-2021, Wazuh Inc.
 *
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <fstream>
#include <stdio.h>
#include <memory>
#include <json.hpp>
#include "dbsync.h"
#include "cmdArgsHelper.h"
#include "action.hpp"

static void loggerFunction(const char* msg)
{
    std::cout << "Msg: " << msg << std::endl;
}

int main(int argc, const char* argv[])
{

    CmdLineArgs args{argc, argv};
    auto config = args.config();
    auto input = args.inputData();
    std::string action = input["action"];
    std::unique_ptr<TestAction> testAction = nullptr;

    if (action == "DB_INSERT")
    {
        testAction = std::make_unique<InsertAction>(input["table"], input["data"]);
    }
    else if (action == "DB_UPDATE")
    {
        testAction = std::make_unique<UpdateAction>(input["table"], input["data"]);
    }
    else if (action == "DB_REMOVE")
    {
        testAction = std::make_unique<RemoveAction>(input["table"], input["data"]);
    }
    else
    {
        throw std::runtime_error
        {
            "Action not valid."};
    }

    testAction->execute();
    return 0;
}
