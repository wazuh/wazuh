#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>

#include "combinatorBuilderChain.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderHelperFilter.hpp"
#include "opBuilderHelperMap.hpp"
#include "stageBuilderCheck.hpp"
#include "stageBuilderNormalize.hpp"
#include "testUtils.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

class opBuilderHelperJsonDeleteFieldsTestSuite : public testing::Test
{
protected:
    // Per-test-suite set-up.
    // Called before the first test in this test suite.
    static void SetUpTestSuite() {}

    // Per-test-suite tear-down.
    // Called after the last test in this test suite.
    static void TearDownTestSuite() { return; }
};

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, Builds)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "qttyOfDeletedFields": "+json_delete_fields/Field_1/Field_2"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(
        bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr));
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, CantBuildWithoutParameter)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "qttyOfDeletedFields": "+json_delete_fields"
                }
            }
        ]
    })"};

    ASSERT_THROW(bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr),
                 std::runtime_error);
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, CantBuildWithEmptyParameter)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "qttyOfDeletedFields": "+json_delete_fields//"
                }
            }
        ]
    })"};

    ASSERT_THROW(bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr),
                 std::runtime_error);
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, CantBuildWithoutStringParameter)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "qttyOfDeletedFields": "+json_delete_fields//2"
                }
            }
        ]
    })"};

    ASSERT_THROW(bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr),
                 std::runtime_error);
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, ExecutesWithTwoDeletes)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/Field_1/Field_2"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": "1",
                "Field_2": "2",
                "Third": "Value"
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 2);
    ASSERT_THROW(expected[0]->getEventValue("/Field_1"), std::invalid_argument);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, ExecutesWithReference)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/$Field_1/Field_2"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": "/Third",
                "Field_2": "2",
                "Third":""
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 2);
    ASSERT_EQ(expected[0]->getEventValue("/Field_1"), "/Third");
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
    ASSERT_THROW(expected[0]->getEventValue("/Third"), std::invalid_argument);
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, CantExecuteNonStringReference)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/$Field_1/Field_2"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": 8,
                "Field_2": "2",
                "Third": 9
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/Field_1"), 8);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
    ASSERT_EQ(expected[0]->getEventValue("/Third").GetInt(), 9);
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, DeleteJustFirstReference)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/$Field_1/$Field_2"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": "/Field_2",
                "Field_2": "Value_2",
                "Third": 9
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 1);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, CantDeleteUnexistentField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/Field_2"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": "Value"
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 0);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, CantDeleteUnexistentField_2)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/Field_2/Field_1"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": "Value"
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 1);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
    ASSERT_THROW(expected[0]->getEventValue("/Field_1"), std::invalid_argument);
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, DeleteFullNestedField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/Field_2.a"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": "Value_1",
                "Field_2":
                    { "a" : "Value_2" },
                "Third": 9
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 1);
    ASSERT_TRUE(expected[0]->getEventValue("/Field_2").GetObject().ObjectEmpty());
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, DeleteSingleNestedField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/Field_2.a"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": "Value_1",
                "Field_2":
                    { "a" : "Value_1_a",
                      "b" : "Value_1_b"
                    },
                "Third": 9
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 1);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2/a").GetString(),
                 std::invalid_argument);
    ASSERT_STREQ(expected[0]->getEventValue("/Field_2/b").GetString(), "Value_1_b");
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, DeleteSingleArrayField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/Field_2.0.key_a"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": "Value",
                "Field_2":
                    [
                        { "key_a" : "Value_A"},
                        { "key_a" : "Value_B"},
                        { "key_a" : "Value_C"}
                    ]
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 1);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2/0/key_a").GetString(),
                 std::invalid_argument);
    ASSERT_STREQ(expected[0]->getEventValue("/Field_2/1/key_a").GetString(), "Value_B");
    ASSERT_STREQ(expected[0]->getEventValue("/Field_2/2/key_a").GetString(), "Value_C");
}

TEST_F(opBuilderHelperJsonDeleteFieldsTestSuite, DeleteFullArrayField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "deletedFields": "+json_delete_fields/Field_2"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_1": "Value",
                "Field_2":
                    [
                        { "key_a" : "Value_A"},
                        { "key_a" : "Value_B"},
                        { "key_a" : "Value_C"}
                    ]
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperJsonDeleteFields(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_EQ(expected[0]->getEventValue("/deletedFields").GetInt(), 1);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2").GetString(),
                 std::invalid_argument);
}
