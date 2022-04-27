/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include "testUtils.hpp"

#include <vector>
#include <filesystem>
#include <fstream>
#include <iostream>

#include "opBuilderFileOutput.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

auto createEvent = [](const char * json){
    return std::make_shared<EventHandler>(std::make_shared<Document>(json));
};

TEST(opBuilderFileOutput, Builds)
{
    Document doc{R"({
        "file":
            {"path": "value"}
    })"};

    ASSERT_NO_THROW(bld::opBuilderFileOutput(doc.get("/file"), tr));
}

TEST(opBuilderFileOutput, BuildsOperates)
{
    Document doc{R"({
        "file":
            {"path": "/tmp/fileOutputTest.txt"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createEvent(R"(
                {"field":"value"}
            )"));
            s.on_completed();
        });
    Lifter lift = bld::opBuilderFileOutput(doc.get("/file"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 4);

    const string expectedWrite =
R"({"field":"value"}
{"field":"value"}
{"field":"value"}
{"field":"value"}
)";

    string filepath{"/tmp/fileOutputTest.txt"};
    std::ifstream ifs(filepath);
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    const string got = buffer.str();
    // cerr << got << std::endl;
    // cerr << expectedWrite << std::endl;
    std::filesystem::remove(filepath);

    ASSERT_EQ(got, expectedWrite);
}
