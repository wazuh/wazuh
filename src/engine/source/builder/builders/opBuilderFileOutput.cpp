/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "opBuilderFileOutput.hpp"

#include <memory>
#include <stdexcept>
#include <string>

#include "outputs/file.hpp"
#include <logging/logging.hpp>

#include <fmt/format.h>

namespace builder::internals::builders
{

base::Lifter opBuilderFileOutput(const base::DocumentValue &def, types::TracerFn tr)
{
    // Check that input is as expected and throw exception otherwise
    if (!def.IsObject())
    {
        auto msg = fmt::format(
            "File output builder expects value to be an object, but got [{}]",
            def.GetType());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(msg);
    }
    if (def.GetObject().MemberCount() != 1)
    {
        auto msg = fmt::format("File output builder expects value to have only "
                               "one key, but got [{}]",
                               def.GetObject().MemberCount());
        WAZUH_LOG_ERROR("{}", msg);
        throw std::invalid_argument(msg);
    }

    std::string path;
    try
    {
        path = def.MemberBegin()->value.GetString();
    }
    catch (std::exception &e)
    {
        const char *msg =
            "File output builder encountered exception on building path.";
        WAZUH_LOG_ERROR("{} From exception: [{}]", msg, e.what());
        std::throw_with_nested(std::runtime_error(msg));
    }

    return [=](const base::Observable &input) -> base::Observable
    {
        auto filePtr = std::make_shared<outputs::FileOutput>(path);
        input.subscribe([=](auto v) { filePtr->write(v); },
                        [](std::exception_ptr e) {
                            WAZUH_LOG_ERROR("{}", rxcpp::util::what(e).c_str());
                        },
                        [=]() { /* filePtr->close(); */ });
        return input;
    };
}

} // namespace builder::internals::builders
