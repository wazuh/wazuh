#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>

#include "combinatorBuilderChain.hpp"
#include "opBuilderHelperMap.hpp"
#include "opBuilderCondition.hpp"
#include "opBuilderHelperFilter.hpp"
#include "stageBuilderCheck.hpp"
#include "stageBuilderNormalize.hpp"
#include "testUtils.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};


class opBuilderHelperStringConcat : public testing::Test {
 protected:
  // Per-test-suite set-up.
  // Called before the first test in this test suite.
  // Can be omitted if not needed.
  static void SetUpTestSuite() {

    Registry::registerBuilder("check", bld::stageBuilderCheck);
    Registry::registerBuilder("condition", bld::opBuilderCondition);
    Registry::registerBuilder("middle.condition", bld::middleBuilderCondition);
    Registry::registerBuilder("middle.helper.exists", bld::opBuilderHelperExists);
    Registry::registerBuilder("combinator.chain", bld::combinatorBuilderChain);
    Registry::registerBuilder("helper.s_concat", bld::opBuilderHelperStringConcat);

  }

  // Per-test-suite tear-down.
  // Called after the last test in this test suite.
  // Can be omitted if not needed.
  static void TearDownTestSuite() {
      return;
  }

  // You can define per-test set-up logic as usual.
  //void SetUp() override { ... }

  // You can define per-test tear-down logic as usual.
  //void TearDown() override { ... }

  // Some expensive resource shared by all tests.
  //static T* shared_resource_;
};


TEST_F(opBuilderHelperStringConcat, Builds)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieldToTranf": "+s_concat/First/Second"
                }
            }
        ]
    })"};

    ASSERT_NO_THROW(bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr));
}

TEST_F(opBuilderHelperStringConcat, WrongNumberOfArguments)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieldToTranf": "+s_concat/First"
                }
            }
        ]
    })"};

    ASSERT_THROW(bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr),
                 std::runtime_error);
}

TEST_F(opBuilderHelperStringConcat, EmptyArgument)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieldToTranf": "+s_concat/First/"
                }
            }
        ]
    })"};

    ASSERT_THROW(bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr),
                 std::runtime_error);
}

TEST_F(opBuilderHelperStringConcat, BasicUsage)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieldToTranf": "+s_concat/First/Second"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"fieldToTranf": "something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/fieldToTranf").GetString(),
                 "FirstSecond");
}

TEST_F(opBuilderHelperStringConcat, SimpleWithOneReference)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieldResult": "+s_concat/First/$fieldToTranf"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"fieldToTranf": "Something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/fieldResult").GetString(),
                 "FirstSomething");
}

TEST_F(opBuilderHelperStringConcat, SimpleWithOneSelfReference)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieldToTranf": "+s_concat/First/$fieldToTranf"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"fieldToTranf": "Something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/fieldToTranf").GetString(),
                 "FirstSomething");
}

TEST_F(opBuilderHelperStringConcat, DoubleWithReferences)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Result": "+s_concat/$fieldToTranf/$anotherField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"anotherField": "OneThing",
                "fieldToTranf": "Something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/Result").GetString(),
                 "SomethingOneThing");
}

TEST_F(opBuilderHelperStringConcat, DoubleWithOneSelfReferences)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "anotherField": "+s_concat/$fieldToTranf/$anotherField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"anotherField": "OneThing",
                "fieldToTranf": "Something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/anotherField").GetString(),
                 "SomethingOneThing");
}

TEST_F(opBuilderHelperStringConcat, DoubleWithOneSelfReferencesSecondaryAssignment)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieldToTranf": "+s_concat/$fieldToTranf/$anotherField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"anotherField": "OneThing",
                "fieldToTranf": "Something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/fieldToTranf").GetString(),
                 "SomethingOneThing");
}

TEST_F(opBuilderHelperStringConcat, OneReferencesNotString)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field": "+s_concat/$fieldToTranf/$anotherField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"anotherField": "OneThing",
                "fieldToTranf": 1}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_THROW(expected[0]->getEvent()->get("/Field"), std::invalid_argument);
}

TEST_F(opBuilderHelperStringConcat, OneEmptyReferenceWithPresentField)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "anotherField": "+s_concat/$fieldToTranf/$anotherField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"anotherField": "OneThing",
                "fieldToTranf": 1}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/anotherField").GetString(), "OneThing");
}

TEST_F(opBuilderHelperStringConcat, OneEmptyReference)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field": "+s_concat/$fieldToTranf/$anotherField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"anotherField": "OneThing",
                "fieldToTranf": 1}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_THROW(expected[0]->getEvent()->get("/Field"), std::invalid_argument);
}

TEST_F(opBuilderHelperStringConcat, ReferenceDoesntExist)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieldToTranf": "+s_concat/$fieldToTranf/$anotherField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"fieldToTranf": "something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/fieldToTranf").GetString(), "something");
}

TEST_F(opBuilderHelperStringConcat, BasicUsageThreeArguments)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field": "+s_concat/First/Second/Third"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"fieldToTranf": "something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/Field").GetString(), "FirstSecondThird");
}

TEST_F(opBuilderHelperStringConcat, BasicUsageThreeArgumentsMiddleEmpty)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field": "+s_concat/First//Third"
                }
            }
        ]
    })"};

    ASSERT_THROW(bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr),
                 std::runtime_error);
}

TEST_F(opBuilderHelperStringConcat, BasicUsageLotOfArguments)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "Field": "+s_concat/A/B/C/D/E/F/G/H/I/J/K/L/M/N/O/P/Q/R/S/T/U/V/W/X/Y/Z"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"fieldToTranf": "something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/Field").GetString(),
                 "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}

TEST_F(opBuilderHelperStringConcat, EmptyReference)
{
    Document doc {R"({
        "normalize":
        [
            {
                "map":
                {
                    "fieldToTranf": "+s_concat/something/$anotherField"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"anotherField": ""}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::opBuilderHelperStringConcat(doc.get("/normalize/0/map"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/fieldToTranf").GetString(), "something");
}

TEST_F(opBuilderHelperStringConcat, DoubleUsage)
{

    Document doc{R"({
        "normalize":
        [
            {
                "map":
                {
                    "FieldA": "+s_concat/A/B/C",
                    "FieldB": "+s_concat/$FieldA/D/E/F"
                }
            }
        ]
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(createSharedEvent(R"(
                {"FieldB": "something"}
            )"));
            s.on_completed();
        });

    Lifter lift = bld::stageBuilderNormalize(doc.get("/normalize"), tr);
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 1);
    ASSERT_STREQ(expected[0]->getEvent()->get("/FieldB").GetString(), "ABCDEF");
}

TEST_F(opBuilderHelperStringConcat, ComplexUsage)
{

    Document doc {R"({
        "normalize": [
            {
                "map":
                {
                    "FieldA": "+s_concat/A/B/C",
                    "FieldB": "+s_concat/$FieldA/D/E/F"
                }
            },
            {
                "check":
                [
                    {"FieldX": "+exists"}
                ],
                "map":
                {
                    "FieldX": "+s_concat/1/2/$FieldA"
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

    auto eventsCount = 2;
    auto inputObjectOne = createSharedEvent(R"({"FieldB": "something"})");
    auto inputObjectTwo = createSharedEvent(R"({"FieldX": "somethingElse"})");

    inputSubject.get_subscriber().on_next(inputObjectOne);
    inputSubject.get_subscriber().on_next(inputObjectTwo);

    ASSERT_EQ(expected.size(), eventsCount);
    ASSERT_STREQ(expected[0]->getEvent()->get("/FieldB").GetString(), "ABCDEF");
    ASSERT_STREQ(expected[1]->getEvent()->get("/FieldX").GetString(), "12ABC");
}
