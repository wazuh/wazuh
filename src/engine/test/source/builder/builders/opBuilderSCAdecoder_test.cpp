/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/socketInterface/unixSecureStream.hpp>

#include "combinatorBuilderChain.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderHelperFilter.hpp"
#include "opBuilderHelperMap.hpp"
#include "opBuilderMapValue.hpp"
#include "opBuilderSCAdecoder.hpp"
#include "opBuilderWdbSync.hpp"
#include "socketAuxiliarFunctions.hpp"
#include "stageBuilderCheck.hpp"
#include "stageBuilderNormalize.hpp"
#include "testUtils.hpp"
#include "wdb/wdb.hpp"

namespace
{

using namespace base;
using namespace wazuhdb;
namespace bld = builder::internals::builders;
namespace unixStream = base::utils::socketInterface;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

class opBuilderSCAdecoderTest : public ::testing::Test
{

protected:
    // Per-test-suite set-up.
    // Called before the first test in this test suite.
    static void SetUpTestSuite()
    {
        Registry::registerBuilder("helper.s_concat", bld::opBuilderHelperStringConcat);
        Registry::registerBuilder("check", bld::stageBuilderCheck);
        Registry::registerBuilder("condition", bld::opBuilderCondition);
        Registry::registerBuilder("middle.condition", bld::middleBuilderCondition);
        Registry::registerBuilder("middle.helper.exists", bld::opBuilderHelperExists);
        Registry::registerBuilder("combinator.chain", bld::combinatorBuilderChain);
        Registry::registerBuilder("map.value", bld::opBuilderMapValue);
        Registry::registerBuilder("helper.wdb_query", bld::opBuilderWdbSyncQuery);
        Registry::registerBuilder("helper.sca_decoder", bld::opBuilderSCAdecoder);
    }

    // Per-test-suite tear-down.
    // Called after the last test in this test suite.
    static void TearDownTestSuite() { return; }
};

// Build ok
TEST_F(opBuilderSCAdecoderTest, BuildSimplest)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "wdb.result": "+sca_decoder"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(bld::opBuilderSCAdecoder(doc.get("/normalize/0/map"), tr));
}

TEST_F(opBuilderSCAdecoderTest, typeChecking)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "sca_result": "+sca_decoder"
                }
            }
        ]
    })"};

    auto normalize = bld::stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 1;
    auto inputObjectOne =
        createSharedEvent(R"({"event":{"original":{"message":{"type":"dump_end"}}}})");

    inputSubject.get_subscriber().on_next(inputObjectOne);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_FALSE(expected[0]->getEvent()->get("/sca_result").GetBool());
}
} // namespace
