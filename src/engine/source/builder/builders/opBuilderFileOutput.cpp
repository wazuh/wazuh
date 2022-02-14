/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderFileOutput.hpp"

#include <glog/logging.h>
#include <memory>
#include <stdexcept>
#include <string>

#include "file.hpp"

using namespace std;

namespace builder::internals::builders
{

types::Lifter opBuilderFileOutput(const types::DocumentValue & def)
{
    // Check that input is as expected and throw exception otherwise
    if (!def.IsObject())
    {
        auto msg = "File output builder expects value to be an object, but got " + def.GetType();
        LOG(ERROR) << msg << endl;
        throw std::invalid_argument(msg);
    }
    if (def.GetObject().MemberCount() != 1)
    {
        auto msg = "File output builder expects value to have only one key, but got" + def.GetObject().MemberCount();
        LOG(ERROR) << msg << endl;
        throw std::invalid_argument(msg);
    }

    string path;
    try
    {
        path = def.MemberBegin()->value.GetString();
    }
    catch (exception & e)
    {
        string msg = "File output builder encountered exception on building path.";
        LOG(ERROR) << msg << " From exception: " << e.what() << endl;
        std::throw_with_nested(runtime_error(msg));
    }

    return [=](const types::Observable & input) -> types::Observable
    {
        auto filePtr = make_shared<outputs::FileOutput>(path);
        input.subscribe([=](auto v) { filePtr->write(v); },
                        [](std::exception_ptr e) { LOG(ERROR) << rxcpp::util::what(e).c_str() << endl; },
                        [=]() { // filePtr->close();
                        });
        return input;
    };
}

} // namespace builder::internals::builders
