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

#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>

#include "combinatorBuilderBroadcast.hpp"
#include "opBuilderFileOutput.hpp"
#include "stageBuilderOutputs.hpp"

using namespace builder::internals::builders;

TEST(StageBuilderOutputs, BuildsAllNonRegistered)
{
    Document doc{R"({
        "outputs": [
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
        ]
    })"};

    ASSERT_THROW(builders::stageBuilderOutputs(doc.get("/outputs")), std::_Nested_exception<std::runtime_error>);
}

TEST(StageBuilderOutputs, Builds)
{
    BuilderVariant c = opBuilderFileOutput;
    Registry::registerBuilder("file", c);
    c = combinatorBuilderBroadcast;
    Registry::registerBuilder("combinator.broadcast", c);

    Document doc{R"({
        "outputs": [
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
        ]
    })"};

    ASSERT_NO_THROW(builders::stageBuilderOutputs(doc.get("/outputs")));
}

TEST(StageBuilderOutputs, BuildsOperates)
{
    Document doc{R"({
        "outputs": [
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"value"}
            )"));
            s.on_next(std::make_shared<json::Document>(R"(
                {"field":"value"}
            )"));
            s.on_completed();
        });
    Lifter lift = builders::stageBuilderOutputs(doc.get("/outputs"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 8);

    const string expectedWrite =
        R"({"field":"value"}
{"field":"value"}
{"field":"value"}
{"field":"value"}
)";

    string filepath1{"/tmp/stageOutputsTest1.txt"};
    string filepath2{"/tmp/stageOutputsTest2.txt"};
    std::ifstream ifs(filepath1);
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    const string got1 = buffer.str();

    ifs.open(filepath2);
    buffer << ifs.rdbuf();
    const string got2 = buffer.str();
    // cerr << got << std::endl;
    // cerr << expectedWrite << std::endl;
    std::filesystem::remove(filepath1);
    std::filesystem::remove(filepath2);

    ASSERT_EQ(got1, expectedWrite);
    ASSERT_EQ(got2, expectedWrite);
}
