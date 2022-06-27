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

class opBuilderHelperDeleteFieldTestSuite : public testing::Test
{
protected:
    // Per-test-suite set-up.
    // Called before the first test in this test suite.
    static void SetUpTestSuite()
    {
        Registry::registerBuilder("helper.delete_field",
                                  builders::opBuilderHelperDeleteField);
    }

    // Per-test-suite tear-down.
    // Called after the last test in this test suite.
    static void TearDownTestSuite() { return; }
};

TEST_F(opBuilderHelperDeleteFieldTestSuite, Builds)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "qttyOfDeletedFields": "+delete_field"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(bld::opBuilderHelperDeleteField(doc.get("/normalize/0/map"), tr));
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, CantBuildWithtParameter)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "qttyOfDeletedFields": "+delete_field/Argument"
                }
            }
        ]
    })"};

    ASSERT_THROW(bld::opBuilderHelperDeleteField(doc.get("/normalize/0/map"), tr),
                 std::runtime_error);
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, CantBuildWithEmptyParameter)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "": "+delete_field//"
                }
            }
        ]
    })"};

    ASSERT_THROW(bld::opBuilderHelperDeleteField(doc.get("/normalize/0/map"), tr),
                 std::runtime_error);
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, ExecutesWithSimpleDelete)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field_1": "+delete_field"
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

    Lifter lift = bld::opBuilderHelperDeleteField(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEventValue("/Field_2").GetString(), "2");
    ASSERT_THROW(expected[0]->getEventValue("/Field_1"), std::invalid_argument);
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, DeleteTwoFields)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field_1": "+delete_field",
                    "Field_2": "+delete_field"
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
    auto inputObject = createSharedEvent(R"(
                {
                "Field_1": 8,
                "Field_2": "2",
                "Field_3": 9
                }
            )");

    inputSubject.get_subscriber().on_next(inputObject);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_THROW(expected[0]->getEventValue("/Field_1"), std::invalid_argument);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
    ASSERT_EQ(expected[0]->getEventValue("/Field_3").GetInt(), 9);
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, DeleteTwoTimesSameField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field_1": "+delete_field",
                    "Field_1": "+delete_field"
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
    auto inputObject = createSharedEvent(R"(
                {
                "Field_1": 8,
                "Field_2": 9
                }
            )");

    inputSubject.get_subscriber().on_next(inputObject);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_THROW(expected[0]->getEventValue("/Field_1"), std::invalid_argument);
    ASSERT_EQ(expected[0]->getEventValue("/Field_2").GetInt(), 9);
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, DeleteTwoFieldsOneUnexisting)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field_3": "+delete_field",
                    "Field_1": "+delete_field"
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
    auto inputObject = createSharedEvent(R"(
                {
                "Field_1": 8,
                "Field_2": "2"
                }
            )");

    inputSubject.get_subscriber().on_next(inputObject);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_THROW(expected[0]->getEventValue("/Field_1"), std::invalid_argument);
    ASSERT_STREQ(expected[0]->getEventValue("/Field_2").GetString(), "2");
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, CantDeleteUnexistentField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field_2": "+delete_field"
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

    Lifter lift = bld::opBuilderHelperDeleteField(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEventValue("/Field_1").GetString(), "Value");
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, DeleteFullNestedField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field_2": "+delete_field"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                "Field_2":
                    { "a" : "Value_2" },
                "Third": 9
                }
            )"));
        s.on_completed();
    });

    Lifter lift = bld::opBuilderHelperDeleteField(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, DeleteSingleNestedField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field_2.a": "+delete_field"
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

    Lifter lift = bld::opBuilderHelperDeleteField(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2/a").GetString(),
                 std::invalid_argument);
    ASSERT_STREQ(expected[0]->getEventValue("/Field_2/b").GetString(), "Value_1_b");
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, DeleteSingleArrayField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field_2.0.key_a": "+delete_field"
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

    Lifter lift = bld::opBuilderHelperDeleteField(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2/0/key_a").GetString(),
                 std::invalid_argument);
    ASSERT_STREQ(expected[0]->getEventValue("/Field_2/1/key_a").GetString(), "Value_B");
    ASSERT_STREQ(expected[0]->getEventValue("/Field_2/2/key_a").GetString(), "Value_C");
}

TEST_F(opBuilderHelperDeleteFieldTestSuite, DeleteFullArrayField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field_2": "+delete_field"
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

    Lifter lift = bld::opBuilderHelperDeleteField(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_THROW(expected[0]->getEventValue("/Field_2"), std::invalid_argument);
}
