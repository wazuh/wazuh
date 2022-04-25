/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>

#include "combinatorBuilderBroadcast.hpp"
#include "combinatorBuilderChain.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderConditionReference.hpp"
#include "opBuilderConditionValue.hpp"
#include "opBuilderHelperFilter.hpp"
#include "opBuilderMap.hpp"
#include "opBuilderMapReference.hpp"
#include "opBuilderMapValue.hpp"
#include "stageBuilderCheck.hpp"
#include "stageBuilderNormalize.hpp"
#include "testUtils.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

/**

YML:

---
normalize:
- map:
    mapped.field1: value
    mapped.field2: 2
    mapped.field3: "$field1"
    mapped.field4: true
    mapped.field5: false
- check:
  - mapped.field1: value
  - mapped.field2: 2
  - mapped.field3: "$field1"
  - mapped.field4: true
  - mapped.field5: "+exists"
  map:
    mapped.field6: value
    mapped.field7: 2
    mapped.field8: "$field1"
    mapped.field9: true
    mapped.field10: false

JSON:

{
    "normalize": [
        {
            "map": {
                "mapped.field1": "value",
                "mapped.field2": 2,
                "mapped.field3": "$field1",
                "mapped.field4": true,
                "mapped.field5": false
            }
        },
        {
            "check": [
                {"mapped.field1": "value"},
                {"mapped.field2": 2},
                {"mapped.field3": "$field1"},
                {"mapped.field4": true},
                {"mapped.field5": "+exists"}
            ],
            "map": {
                "mapped.field6": "value",
                "mapped.field7": 2,
                "mapped.field8": "$field1",
                "mapped.field9": true,
                "mapped.field10": false
            }
        }
    ]
}

*/

TEST(StageBuilderNormalize, BuildFullNormalizeNonRegistered)
{
    Document doc {R"({
        "normalize": [
            {
                "map": {
                    "mapped.field1": "value",
                    "mapped.field2": 2,
                    "mapped.field3": "$field1",
                    "mapped.field4": true,
                    "mapped.field5": false
                }
            },
            {
                "check": [
                    {"mapped.field1": "value"},
                    {"mapped.field2": 2},
                    {"mapped.field3": "$field1"},
                    {"mapped.field4": true},
                    {"mapped.field5": "+exists"}
                ],
                "map": {
                    "mapped.field6": "value",
                    "mapped.field7": 2,
                    "mapped.field8": "$field1",
                    "mapped.field9": true,
                    "mapped.field10": false
                }
            }
        ]
    })"};

    ASSERT_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr),
                 std::_Nested_exception<std::runtime_error>);
}

TEST(StageBuilderNormalize, BuildFullNormalize)
{
    BuilderVariant c;

    // "map" operations
    c = opBuilderMapValue;
    Registry::registerBuilder("map.value", c);
    c = opBuilderMapReference;
    Registry::registerBuilder("map.reference", c);
    c = opBuilderMap;
    Registry::registerBuilder("map", c);

    // "check" operations
    c = stageBuilderCheck;
    Registry::registerBuilder("check", c);
    c = opBuilderCondition;
    Registry::registerBuilder("condition", c);
    c = opBuilderConditionValue;
    Registry::registerBuilder("condition.value", c);
    c = opBuilderConditionReference;
    Registry::registerBuilder("condition.reference", c);
    c = opBuilderHelperExists;
    Registry::registerBuilder("helper.exists", c);

    // combinators
    c = combinatorBuilderChain;
    Registry::registerBuilder("combinator.chain", c);
    c = combinatorBuilderBroadcast;
    Registry::registerBuilder("combinator.broadcast", c);

    Document doc {R"({
        "normalize": [
            {
                "map": {
                    "mapped.field1": "value",
                    "mapped.field2": 2,
                    "mapped.field3": "$field1",
                    "mapped.field4": true,
                    "mapped.field5": false
                }
            },
            {
                "check": [
                    {"mapped.field1": "value"},
                    {"mapped.field2": 2},
                    {"mapped.field3": "$field1"},
                    {"mapped.field4": true},
                    {"mapped.field5": "+exists"}
                ],
                "map": {
                    "mapped.field6": "value",
                    "mapped.field7": 2,
                    "mapped.field8": "$field1",
                    "mapped.field9": true,
                    "mapped.field10": false
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr));
}

TEST(StageBuilderNormalize, BuildFullNormalizeReversed)
{
    Document doc {R"({
        "normalize": [
            {
                "check": [
                    {"mapped.field1": "value"},
                    {"mapped.field2": 2},
                    {"mapped.field3": "$field1"},
                    {"mapped.field4": true},
                    {"mapped.field5": "+exists"}
                ],
                "map": {
                    "mapped.field6": "value",
                    "mapped.field7": 2,
                    "mapped.field8": "$field1",
                    "mapped.field9": true,
                    "mapped.field10": false
                }
            },
            {
                "map": {
                    "mapped.field1": "value",
                    "mapped.field2": 2,
                    "mapped.field3": "$field1",
                    "mapped.field4": true,
                    "mapped.field5": false
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr));
}

TEST(StageBuilderNormalize, BuildNormalizeMap)
{
    Document doc {R"({
        "normalize": [
            {
                "map": {
                    "mapped.field1": "value",
                    "mapped.field2": 2,
                    "mapped.field3": "$field1",
                    "mapped.field4": true,
                    "mapped.field5": false
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr));
}

TEST(StageBuilderNormalize, BuildNormalizeCheckMap)
{
    Document doc {R"({
        "normalize": [
            {
                "check": [
                    {"mapped.field1": "value"},
                    {"mapped.field2": 2},
                    {"mapped.field3": "$field1"},
                    {"mapped.field4": true},
                    {"mapped.field5": "+exists"}
                ],
                "map": {
                    "mapped.field6": "value",
                    "mapped.field7": 2,
                    "mapped.field8": "$field1",
                    "mapped.field9": true,
                    "mapped.field10": false
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr));
}

TEST(StageBuilderNormalize, BuildNormalizeEmptyMap)
{
    Document doc {R"({
        "normalize": [
            {
                "map": {}
            }
        ]
    })"};

    ASSERT_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr),
                 std::_Nested_exception<std::invalid_argument>);
}

TEST(StageBuilderNormalize, BuildNormalizeCheckMapEmptyCheck)
{
    Document doc {R"({
        "normalize": [
            {
                "check": [],
                "map": {
                    "mapped.field6": "value",
                    "mapped.field7": 2,
                    "mapped.field8": "$field1",
                    "mapped.field9": true,
                    "mapped.field10": false
                }
            }
        ]
    })"};

    ASSERT_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr),
                 std::_Nested_exception<std::runtime_error>);
}

TEST(StageBuilderNormalize, BuildNormalizeCheckMapEmptyMap)
{
    Document doc {R"({
        "normalize": [
            {
                "check": [
                    {"mapped.field1": "value"},
                    {"mapped.field2": 2},
                    {"mapped.field3": "$field1"},
                    {"mapped.field4": true},
                    {"mapped.field5": "+exists"}
                ],
                "map": {}
            }
        ]
    })"};

    ASSERT_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr),
                 std::_Nested_exception<std::runtime_error>);
}

TEST(StageBuilderNormalize, BuildNormalizeWithCheckNoMap)
{
    Document doc {R"({
        "normalize": [
            {
                "check": [
                    {"mapped.field1": "value"},
                    {"mapped.field2": 2},
                    {"mapped.field3": "$field1"},
                    {"mapped.field4": true},
                    {"mapped.field5": "+exists"}
                ]
            }
        ]
    })"};

    ASSERT_THROW(builders::stageBuilderNormalize(doc.get("/normalize"), tr),
                 std::_Nested_exception<std::invalid_argument>);
}

// TODO: fix this test
// TEST(StageBuilderNormalize, BuildsOperates)
// {
//     Document doc {R"({
//         "normalize": [
//             {
//                 "map": {
//                     "mapped.field1": "value",
//                     "mapped.field2": 2,
//                     "mapped.field3": "$field1",
//                     "mapped.field4": true
//                 }
//             }
//         ]
//     })"};

//     auto normalize = builders::stageBuilderNormalize(doc.get("/normalize"),
//     tr);

//     Observable input = observable<>::create<Event>(
//         [=](auto s)
//         {
//             s.on_next(std::make_shared<json::Document>(R"({
//                 "map": {
//                     "field1": "value",
//                     "field2": 2,
//                     "field3": "value",
//                     "field4": true,
//                     "field5": "+exists"
//                 }
//             })"));
//             // TODO: fix json interfaces to dont throw
//             // s.on_next(std::make_shared<json::Document>(R"(
//             //     {"field":"values"}
//             // )"));
//             s.on_next(std::make_shared<json::Document>(R"({
//                 "map": {
//                     "field1": "value",
//                     "field2": 2,
//                     "field3": "value",
//                     "field4": true,
//                     "field5": "+exists",
//                     "field6": "+exists"
//                 }
//             })"));
//             // s.on_next(std::make_shared<json::Document>(R"(
//             //     {"otherfield":1}
//             // )"));
//             s.on_completed();
//         });

//     Observable output = normalize(input);

// vector<Event> expected;
// output.subscribe([&](Event e) { expected.push_back(e); });
// ASSERT_EQ(expected.size(), 2);
// for (auto e : expected)
// {
//     ASSERT_STREQ(e->get("/mapped/field1").GetString(), "value");
//     ASSERT_EQ(e->get("/mapped/field2").GetInt(), 2);
//     ASSERT_STREQ(e->get("/mapped/field3").GetString(), "value");
//     ASSERT_TRUE(e->get("/mapped/field4").GetBool());
// }
// }
