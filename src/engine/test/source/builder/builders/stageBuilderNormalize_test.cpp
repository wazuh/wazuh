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
using namespace builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

/**

Example of a (dummy) "normalize" configuration

YML:

---
normalize:
- map:
    field1: value
    field2: 2
    field3: "$field1"
    field4: true
    field5: false
- check:
  - field1: value
  - field2: 2
  - field3: "$field1"
  - field4: true
  - field5: "+exists"
  map:
    field6: value
    field7: 2
    field8: "$field1"
    field9: true
    field10: false

JSON:

{
    "normalize":
    [
        {
            "map":
            {
                "field1": "value",
                "field2": 2,
                "field3": "$field1",
                "field4": true,
                "field5": false
            }
        },
        {
            "check":
            [
                {"field1": "value"},
                {"field2": 2},
                {"field3": "$field1"},
                {"field4": true},
                {"field5": "+exists"}
            ],
            "map":
            {
                "field6": "value",
                "field7": 2,
                "field8": "$field1",
                "field9": true,
                "field10": false
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
                        "field1": "value",
                        "field2": 2,
                        "field3": "$field1",
                        "field4": true,
                        "field5": false
                    }
                },
                {
                    "check":
                    [
                        {"field1": "value"},
                        {"field2": 2},
                        {"field3": "$field1"},
                        {"field4": true},
                        {"field5": "+exists"}
                    ],
                    "map":
                    {
                        "field6": "value",
                        "field7": 2,
                        "field8": "$field1",
                        "field9": true,
                        "field10": false
                    }
                }
            ]
        })"};

    ASSERT_THROW(stageBuilderNormalize(doc.get("/normalize"), tr),
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
                        "field1": "value",
                        "field2": 2,
                        "field3": "$field1",
                        "field4": true,
                        "field5": false
                    }
                },
                {
                    "check":
                    [
                        {"field1": "value"},
                        {"field2": 2},
                        {"field3": "$field1"},
                        {"field4": true},
                        {"field5": "+exists"}
                    ],
                    "map":
                    {
                        "field6": "value",
                        "field7": 2,
                        "field8": "$field1",
                        "field9": true,
                        "field10": false
                    }
                }
            ]
        })"};

    ASSERT_NO_THROW(stageBuilderNormalize(doc.get("/normalize"), tr));
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
                        {"field1": "value"},
                        {"field2": 2},
                        {"field3": "$field1"},
                        {"field4": true},
                        {"field5": "+exists"}
                    ],
                    "map":
                    {
                        "field6": "value",
                        "field7": 2,
                        "field8": "$field1",
                        "field9": true,
                        "field10": false
                    }
                },
                {
                    "map":
                    {
                        "field1": "value",
                        "field2": 2,
                        "field3": "$field1",
                        "field4": true,
                        "field5": false
                    }
                }
            ]
        })"};

    ASSERT_NO_THROW(stageBuilderNormalize(doc.get("/normalize"), tr));
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
                        "field1": "value",
                        "field2": 2,
                        "field3": "$field1",
                        "field4": true,
                        "field5": false
                    }
                }
            ]
        })"};

    ASSERT_NO_THROW(stageBuilderNormalize(doc.get("/normalize"), tr));
}

TEST(StageBuilderNormalize, BuildNormalizeCheckMap)
{
    Document doc {R"({
        "normalize":
        [
            {
                "check":
                [
                    {"field1": "value"},
                    {"field2": 2},
                    {"field3": "$field1"},
                    {"field4": true},
                    {"field5": "+exists"}
                ],
                "map":
                {
                    "field6": "value",
                    "field7": 2,
                    "field8": "$field1",
                    "field9": true,
                    "field10": false
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(stageBuilderNormalize(doc.get("/normalize"), tr));
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

    ASSERT_THROW(stageBuilderNormalize(doc.get("/normalize"), tr),
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
                        "field6": "value",
                        "field7": 2,
                        "field8": "$field1",
                        "field9": true,
                        "field10": false
                    }
                }
            ]
        })"};

    ASSERT_THROW(stageBuilderNormalize(doc.get("/normalize"), tr),
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
                        {"field1": "value"},
                        {"field2": 2},
                        {"field3": "$field1"},
                        {"field4": true},
                        {"field5": "+exists"}
                    ],
                    "map": {}
                }
            ]
        })"};

    ASSERT_THROW(stageBuilderNormalize(doc.get("/normalize"), tr),
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
                        {"field1": "value"},
                        {"field2": 2},
                        {"field3": "$field1"},
                        {"field4": true},
                        {"field5": "+exists"}
                    ]
                }
            ]
        })"};

    ASSERT_THROW(stageBuilderNormalize(doc.get("/normalize"), tr),
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

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    auto eventsCount = 3;
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                s.on_next(createSharedEvent(R"(
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
        ASSERT_STREQ(e->getEvent()->get("/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->getEvent()->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->getEvent()->get("/field4").GetBool());
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

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    auto eventsCount = 3;
    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            for (int i = 0; i < eventsCount; i++)
            {
                s.on_next(createSharedEvent(R"(
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
        ASSERT_STREQ(e->getEvent()->get("/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->getEvent()->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->getEvent()->get("/field4").GetBool());
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

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 3;
    auto inputObject = createSharedEvent(R"(
                        {
                                "field1": "value",
                                "field2": 2,
                                "field3": "value3",
                                "field4": true,
                                "field5": "+exists",
                                "field6": "+exists"
                        })");
    for (int i = 0; i < eventsCount; i++)
    {
        inputSubject.get_subscriber().on_next(inputObject);
    }

    ASSERT_EQ(expected.size(), eventsCount);

    for (auto e : expected)
    {
        ASSERT_STREQ(e->getEvent()->get("/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->getEvent()->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->getEvent()->get("/field4").GetBool());
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

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 3;
    auto inputObject = createSharedEvent(R"(
                        {
                                "field1": "value",
                                "field2": 2,
                                "field3": "value3",
                                "field4": true,
                                "field5": "+exists",
                                "field6": "+exists"
                        })");
    for (int i = 0; i < eventsCount; i++)
    {
        inputSubject.get_subscriber().on_next(inputObject);
    }

    ASSERT_EQ(expected.size(), eventsCount);

    for (auto e : expected)
    {
        ASSERT_STREQ(e->getEvent()->get("/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->getEvent()->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->getEvent()->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, testNormalizeWrongReferenceMapI)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "field3": "$fieldX",
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

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 3;
    auto inputObject = createSharedEvent(R"(
                        {
                                "field1": "value",
                                "field2": 2,
                                "field3": "value3",
                                "field4": true,
                                "field5": "+exists",
                                "field6": "+exists"
                        })");
    for (int i = 0; i < eventsCount; i++)
    {
        inputSubject.get_subscriber().on_next(inputObject);
    }

    ASSERT_EQ(expected.size(), eventsCount);

    for (auto e : expected)
    {
        ASSERT_STREQ(e->getEvent()->get("/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->getEvent()->get("/field3").GetString(), "value3");
        ASSERT_FALSE(e->getEvent()->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, testNormalizeWrongReferenceMapII)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
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
                    "field2": 3,
                    "field3": "$fieldX"
                }
            }
        ]
    })"};

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 3;
    auto inputObject = createSharedEvent(R"(
                        {
                                "field1": "value",
                                "field2": 2,
                                "field3": "value3",
                                "field4": true,
                                "field5": "+exists",
                                "field6": "+exists"
                        })");
    for (int i = 0; i < eventsCount; i++)
    {
        inputSubject.get_subscriber().on_next(inputObject);
    }

    ASSERT_EQ(expected.size(), eventsCount);

    for (auto e : expected)
    {
        ASSERT_STREQ(e->getEvent()->get("/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->getEvent()->get("/field3").GetString(), "value3");
        ASSERT_FALSE(e->getEvent()->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, testNormalizeWrongReferenceCheck)
{
    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "field4": false
                }
            },
            {
                "check":
                [
                    {"field1": "$fieldX"},
                    {"field2": 2}
                ],
                "map":
                {
                    "field3": "$field1"
                }
            }
        ]
    })"};

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 3;
    auto inputObject = createSharedEvent(R"(
                        {
                                "field1": "value",
                                "field2": 2,
                                "field3": "value3",
                                "field4": true,
                                "field5": "+exists",
                                "field6": "+exists"
                        })");
    for (int i = 0; i < eventsCount; i++)
    {
        inputSubject.get_subscriber().on_next(inputObject);
    }

    ASSERT_EQ(expected.size(), eventsCount);

    for (auto e : expected)
    {
        ASSERT_STREQ(e->getEvent()->get("/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/field2").GetInt(), 2);
        ASSERT_STREQ(e->getEvent()->get("/field3").GetString(), "value3");
        ASSERT_FALSE(e->getEvent()->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, testNormalizeMultipleCheck)
{
    Document doc {R"({
        "normalize":
        [
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
                "check":
                [
                    {"field2": 3}
                ],
                "map":
                {
                    "field3": "$field1",
                    "field4": false
                }
            }
        ]
    })"};

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 3;
    auto inputObject = createSharedEvent(R"(
                        {
                                "field1": "value",
                                "field2": 2,
                                "field3": "value3",
                                "field4": true,
                                "field5": "+exists",
                                "field6": "+exists"
                        })");
    for (int i = 0; i < eventsCount; i++)
    {
        inputSubject.get_subscriber().on_next(inputObject);
    }

    ASSERT_EQ(expected.size(), eventsCount);

    for (auto e : expected)
    {
        ASSERT_STREQ(e->getEvent()->get("/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->getEvent()->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->getEvent()->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, testNormalizeMultipleCheckII)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
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
            },
            {
                "check":
                [
                    {"field2": 3}
                ],
                "map":
                {
                    "field3": "$field1"
                }
            }
        ]
    })"};

    auto normalize = stageBuilderNormalize(doc.get("/normalize"), tr);

    rxcpp::subjects::subject<Event> inputSubject;
    inputSubject.get_observable().subscribe([](Event e) {});
    auto inputObservable = inputSubject.get_observable();
    auto output = normalize(inputObservable);

    std::vector<Event> expected;
    output.subscribe([&expected](Event e) { expected.push_back(e); });

    auto eventsCount = 3;
    auto inputObject = createSharedEvent(R"(
                        {
                                "field1": "value",
                                "field2": 2,
                                "field3": "value3",
                                "field4": true,
                                "field5": "+exists",
                                "field6": "+exists"
                        })");
    for (int i = 0; i < eventsCount; i++)
    {
        inputSubject.get_subscriber().on_next(inputObject);
    }

    ASSERT_EQ(expected.size(), eventsCount);

    for (auto e : expected)
    {
        ASSERT_STREQ(e->getEvent()->get("/field1").GetString(), "value");
        ASSERT_EQ(e->getEvent()->get("/field2").GetInt(), 3);
        ASSERT_STREQ(e->getEvent()->get("/field3").GetString(), "value");
        ASSERT_FALSE(e->getEvent()->get("/field4").GetBool());
    }
}

TEST(StageBuilderNormalize, testNormalizeMultipleMapError)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "field4": false
                }
            },
            {
                "map":
                {
                    "field2": 3,
                    "field3": "$field1"
                }
            }
        ]
    })"};

    ASSERT_THROW(stageBuilderNormalize(doc.get("/normalize"), tr),
                 std::_Nested_exception<std::invalid_argument>);
}
