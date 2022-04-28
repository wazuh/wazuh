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

Example of a (dummy) "normalize" configuration

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
    "normalize":
    [
        {
            "map":
            {
                "mapped.field1": "value",
                "mapped.field2": 2,
                "mapped.field3": "$field1",
                "mapped.field4": true,
                "mapped.field5": false
            }
        },
        {
            "check":
            [
                {"mapped.field1": "value"},
                {"mapped.field2": 2},
                {"mapped.field3": "$field1"},
                {"mapped.field4": true},
                {"mapped.field5": "+exists"}
            ],
            "map":
            {
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
    Document doc {R"(
        {
            "normalize":
            [
                {
                    "map":
                    {
                        "mapped.field1": "value",
                        "mapped.field2": 2,
                        "mapped.field3": "$field1",
                        "mapped.field4": true,
                        "mapped.field5": false
                    }
                },
                {
                    "check":
                    [
                        {"mapped.field1": "value"},
                        {"mapped.field2": 2},
                        {"mapped.field3": "$field1"},
                        {"mapped.field4": true},
                        {"mapped.field5": "+exists"}
                    ],
                    "map":
                    {
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
    /** Operations/Stages must be registered only once in the tests (after doing
     * so, they remain registered). */
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

    Document doc {R"(
        {
            "normalize":
            [
                {
                    "map":
                    {
                        "mapped.field1": "value",
                        "mapped.field2": 2,
                        "mapped.field3": "$field1",
                        "mapped.field4": true,
                        "mapped.field5": false
                    }
                },
                {
                    "check":
                    [
                        {"mapped.field1": "value"},
                        {"mapped.field2": 2},
                        {"mapped.field3": "$field1"},
                        {"mapped.field4": true},
                        {"mapped.field5": "+exists"}
                    ],
                    "map":
                    {
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

TEST(StageBuilderNormalize, BuildFullNormalizeInverted)
{
    Document doc {R"(
        {
            "normalize":
            [
                {
                    "check":
                    [
                        {"mapped.field1": "value"},
                        {"mapped.field2": 2},
                        {"mapped.field3": "$field1"},
                        {"mapped.field4": true},
                        {"mapped.field5": "+exists"}
                    ],
                    "map":
                    {
                        "mapped.field6": "value",
                        "mapped.field7": 2,
                        "mapped.field8": "$field1",
                        "mapped.field9": true,
                        "mapped.field10": false
                    }
                },
                {
                    "map":
                    {
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
    Document doc {R"(
        {
            "normalize":
            [
                {
                    "map":
                    {
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
        "normalize":
        [
            {
                "check":
                [
                    {"mapped.field1": "value"},
                    {"mapped.field2": 2},
                    {"mapped.field3": "$field1"},
                    {"mapped.field4": true},
                    {"mapped.field5": "+exists"}
                ],
                "map":
                {
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
    Document doc {R"(
        {
            "normalize":
            [
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
    Document doc {R"(
        {
            "normalize":
            [
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
    Document doc {R"(
        {
            "normalize":
            [
                {
                    "check":
                    [
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
    Document doc {R"(
        {
            "normalize":
            [
                {
                    "check":
                    [
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

TEST(StageBuilderNormalize, testNormalizeMap)
{
    Document doc {R"(
        {
            "normalize":
            [
                {
                    "map":
                    {
                        "field1": "value",
                        "field2": 3,
                        "field3": "$field1",
                        "field4": false,
                        "field5": false
                    }
                }
            ]
        })"};

    auto normalize = builders::stageBuilderNormalize(doc.get("/normalize"), tr);

    auto eventsCount = 3;
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                s.on_next(std::make_shared<json::Document>(R"(
                    {
                        "field1": "value",
                        "field2": 2,
                        "field3": "value3",
                        "field4": true,
                        "field5": "+exists",
                        "field6": "+exists"
                    })"));
            }
            s.on_completed();
        });

    Observable output = normalize(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), eventsCount);
    for (auto e : expected)
    {
        ASSERT_STREQ(e->get("/field1").GetString(), "value");
        ASSERT_EQ(e->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, testNormalizeConditionalMap)
{
    Document doc {R"(
        {
            "normalize":
            [
                {
                    "check":
                    [
                        {"field1": "value"},
                        {"field3": "value3"},
                        {"field4": true}
                    ],
                    "map":
                    {
                        "field2": 3,
                        "field3": "$field1",
                        "field4": false
                    }
                }
            ]
        })"};

    auto normalize = builders::stageBuilderNormalize(doc.get("/normalize"), tr);

    auto eventsCount = 3;
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                s.on_next(std::make_shared<json::Document>(R"(
                    {
                        "field1": "value",
                        "field2": 2,
                        "field3": "value3",
                        "field4": true,
                        "field5": "+exists",
                        "field6": "+exists"
                    })"));
            }
            s.on_completed();
        });

    Observable output = normalize(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), eventsCount);
    for (auto e : expected)
    {
        ASSERT_STREQ(e->get("/field1").GetString(), "value");
        ASSERT_EQ(e->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, testNormalizeMapAndConditionalMap)
{
    Document doc {R"({
        "normalize": [
            {
                "check":
                [
                    {"field1": "value"},
                    {"field2": 2}
                ],
                "map":
                {
                    "field2": 3
                }
            },
            {
                "map":
                {
                    "field3": "$field1",
                    "field4": false
                }
            }
        ]
    })"};

    auto normalize = builders::stageBuilderNormalize(doc.get("/normalize"), tr);

    auto eventsCount = 3;
    auto inputObject = std::make_shared<json::Document>(R"(
                        {
                                "field1": "value",
                                "field2": 2,
                                "field3": "value3",
                                "field4": true,
                                "field5": "+exists",
                                "field6": "+exists"
                        })");
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                s.on_next(inputObject);
            }
            s.on_completed();
        });

    Observable output = normalize(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), eventsCount);
    for (auto e : expected)
    {
        ASSERT_STREQ(e->get("/field1").GetString(), "value");
        ASSERT_EQ(e->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, testNormalizeMapAndConditionalMapInverted)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "field3": "$field1",
                    "field4": false
                }
            },
            {
                "check":
                [
                    {"field1": "value"},
                    {"field2": 2}
                ],
                "map":
                {
                    "field2": 3
                }
            }
        ]
    })"};

    auto normalize = builders::stageBuilderNormalize(doc.get("/normalize"), tr);

    auto eventsCount = 3;
    auto inputObject = std::make_shared<json::Document>(R"(
                        {
                                "field1": "value",
                                "field2": 2,
                                "field3": "value3",
                                "field4": true,
                                "field5": "+exists",
                                "field6": "+exists"
                        })");
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                s.on_next(inputObject);
            }
            s.on_completed();
        });

    Observable output = normalize(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), eventsCount);
    for (auto e : expected)
    {
        ASSERT_STREQ(e->get("/field1").GetString(), "value");
        ASSERT_EQ(e->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->get("/field4").GetBool());
    }
}

/** This test exposes how NOT to use the "on_next" in combination with the
 * "make_shared" to test a full "normalize" operation. */
TEST(StageBuilderNormalize, testNormalizeWrongWayToTest)
{
    Document doc {R"({
        "normalize": [
            {
                "check":
                [
                    {"field1": "value"},
                    {"field2": 2}
                ],
                "map":
                {
                    "field2": 3
                }
            },
            {
                "map":
                {
                    "field3": "$field1",
                    "field4": false
                }
            }
        ]
    })"};

    auto normalize = builders::stageBuilderNormalize(doc.get("/normalize"), tr);

    auto eventsCount = 3;
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                /** WARNING: using the make_shared here results in unexpected
                 * broadcast behavior. */
                s.on_next(std::make_shared<json::Document>(R"(
                            {
                                    "field1": "value",
                                    "field2": 2,
                                    "field3": "value3",
                                    "field4": true,
                                    "field5": "+exists",
                                    "field6": "+exists"
                            })"));
            }
            s.on_completed();
        });

    Observable output = normalize(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), eventsCount);
    for (auto e : expected)
    {
        ASSERT_STREQ(e->get("/field1").GetString(), "value");
        /** The following values should NOT match the original ones. Given the
         * use of the "make_shared" as the parameter of the "on_next", the
         * broadcast operation behaves in an erroneous way. */
        ASSERT_EQ(e->get("/field2").GetInt(), 2);
        ASSERT_STREQ(e->get("/field3").GetString(), "value3");
        ASSERT_TRUE(e->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, unexistandReferencedField)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "field3": "$field10",
                    "field4": false,
                    "field8": "$field9"
                }
            }
        ]
    })"};

    auto normalize = builders::stageBuilderNormalize(doc.get("/normalize"), tr);

    auto eventsCount = 3;
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                /** WARNING: using the make_shared here results in unexpected
                 * broadcast behavior. */
                s.on_next(std::make_shared<json::Document>(R"(
                            {
                                    "field1": "value",
                                    "field2": 2,
                                    "field3": "value3",
                                    "field4": true,
                                    "field5": "+exists",
                                    "field6": "+exists"
                            })"));
            }
            s.on_completed();
        });

    Observable output = normalize(input);

    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), eventsCount);

    for (auto e : expected)
    {
        std::cout << e->prettyStr() << std::endl;
    }
}
