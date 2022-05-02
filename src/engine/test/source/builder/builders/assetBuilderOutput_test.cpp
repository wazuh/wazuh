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

#include "assetBuilderOutput.hpp"
#include "combinatorBuilderBroadcast.hpp"
#include "combinatorBuilderChain.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderConditionReference.hpp"
#include "opBuilderConditionValue.hpp"
#include "opBuilderFileOutput.hpp"
#include "opBuilderHelperFilter.hpp"
#include "stageBuilderCheck.hpp"
#include "stageBuilderOutputs.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg){};

TEST(AssetBuilderOutput, BuildsAllNonRegistered)
{
    Document doc{R"({
        "name": "test",
        "check": [
            {"field": "value"}
        ],
        "outputs": [
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
        ]
    })"};

    ASSERT_THROW(bld::assetBuilderOutput(doc), std::_Nested_exception<std::runtime_error>);
}

TEST(AssetBuilderOutput, Builds)
{
    BuilderVariant c = bld::opBuilderConditionValue;
    Registry::registerBuilder("condition.value", c);
    c = bld::opBuilderConditionReference;
    Registry::registerBuilder("condition.reference", c);
    c = bld::opBuilderHelperExists;
    Registry::registerBuilder("helper.exists", c);
    c = bld::opBuilderHelperNotExists;
    Registry::registerBuilder("helper.not_exists", c);
    c = bld::opBuilderCondition;
    Registry::registerBuilder("condition", c);
    c = bld::combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);
    c = bld::opBuilderFileOutput;
    Registry::registerBuilder("file", c);
    c = bld::combinatorBuilderBroadcast;
    Registry::registerBuilder("combinator.broadcast", c);
    c = bld::stageBuilderOutputs;
    Registry::registerBuilder("outputs", c);
    c = bld::stageBuilderCheck;
    Registry::registerBuilder("check", c);

    Document doc{R"({
        "name": "test",
        "check": [
            {"field": "value"}
        ],
        "outputs": [
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
        ]
    })"};

    ASSERT_NO_THROW(bld::assetBuilderOutput(doc));
}

TEST(AssetBuilderOutput, BuildsOperates)
{
    Document doc{R"({
        "name": "test",
        "check": [
            {"field": "value"}
        ],
        "outputs": [
            {"file":
                {"path": "/tmp/stageOutputsTest1.txt"}
            },
            {"file":
                {"path": "/tmp/stageOutputsTest2.txt"}
            }
        ]
    })"};

    auto input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field1":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"value1"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_next(createSharedEvent(R"(
                {"field":"value"}
            )"));
            s.on_completed();
        }).publish();
    ConnectableT conn = bld::assetBuilderOutput(doc);
    Observable output = conn.connect(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    input.connect();
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
