#include <vector>

#include <gtest/gtest.h>

#include <baseTypes.hpp>

#include "opBuilderHelperMap.hpp"
#include "testUtils.hpp"

using namespace base;
namespace bld = builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

TEST(opBuilderHelperStringConcat, Builds)
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

TEST(opBuilderHelperStringConcat, WrongNumberOfArguments)
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

TEST(opBuilderHelperStringConcat, EmptyArgument)
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

TEST(opBuilderHelperStringConcat, BasicUsage)
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

TEST(opBuilderHelperStringConcat, SimpleWithOneReference)
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

TEST(opBuilderHelperStringConcat, SimpleWithOneSelfReference)
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

TEST(opBuilderHelperStringConcat, DoubleWithReferences)
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

TEST(opBuilderHelperStringConcat, DoubleWithOneSelfReferences)
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

TEST(opBuilderHelperStringConcat, DoubleWithOneSelfReferencesSecondaryAssignment)
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

TEST(opBuilderHelperStringConcat, OneReferencesNotString)
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

TEST(opBuilderHelperStringConcat, OneEmptyReferenceWithPresentField)
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

TEST(opBuilderHelperStringConcat, OneEmptyReference)
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

TEST(opBuilderHelperStringConcat, ReferenceDoesntExist)
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

TEST(opBuilderHelperStringConcat, BasicUsageThreeArguments)
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

TEST(opBuilderHelperStringConcat, BasicUsageThreeArgumentsMiddleEmpty)
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

TEST(opBuilderHelperStringConcat, BasicUsageLotOfArguments)
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
