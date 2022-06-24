/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include <gtest/gtest.h>

#include <vector>

#include <baseTypes.hpp>

#include "opBuilderHelperFilter.hpp"
#include "testUtils.hpp"

using namespace base;
using namespace builder::internals::builders;

using FakeTrFn = std::function<void(std::string)>;
static FakeTrFn tr = [](std::string msg) {
};

// Build ok
TEST(opBuilderHelperStringEqN, Build)
{
    Document doc {R"({
        "check":
            {"sourceField": "+s_eq_n/10/test_value"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperStringEqN(doc.get("/check"), tr));
}

// Build incorrect number of arguments
TEST(opBuilderHelperStringEqN, BuildManyParametersError)
{
    Document doc {R"({
        "check":
            {"sourceField": "+s_eq_n/10/test_value/test_value2"}
    })"};
    ASSERT_THROW(opBuilderHelperStringEqN(doc.get("/check"), tr), std::runtime_error);
}

// Test ok: static values
TEST(opBuilderHelperStringEqN, RawString)
{
    Document doc {R"({
        "check":
            {"sourceField": "+s_eq_n/10/test_value"}
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {"sourceField":"not_test_value"}
            )"));
        s.on_next(createSharedEvent(R"(
                {"sourceField":"test_value_extended"}
            )"));
        s.on_next(createSharedEvent(R"(
                {"otherfield":"value"}
            )"));
        s.on_next(createSharedEvent(R"(
                {"otherfield":"test_value"}
            )"));
        s.on_next(createSharedEvent(R"(
                {"sourceField":"test_value_extended"}
            )"));
        s.on_completed();
    });

    Lifter lift = [=](Observable input) {
        return input.filter(opBuilderHelperStringEqN(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 2);
}

// Test ok: static values
TEST(opBuilderHelperStringEqN, TruncatedRawString)
{
    Document doc {R"({
        "check":
            {"sourceField": "+s_eq_n/10/test_value_extended"}
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {"sourceField":"not_test_value"}
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {"sourceField":"test_value_extended"}
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {"otherfield":"value"}
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {"otherfield":"test_value"}
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {"sourceField":"test_value_extra_extended"}
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {"sourceField":"test_value"}
            )")); // Shall pass
        s.on_completed();
    });

    Lifter lift = [=](Observable input) {
        return input.filter(opBuilderHelperStringEqN(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
}

// Test ok: static values (numbers, compare as string)
TEST(opBuilderHelperStringEqN, RawNumber)
{
    Document doc {R"({
        "check":
            {"sourceField": "+s_eq_n/3/404911"}
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {"sourceField":012404}
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {"sourceField":404911}
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {"otherfield":404}
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {"otherfield":404}
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {"sourceField":404}
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {"sourceField":404666}
            )")); // Shall pass
        s.on_completed();
    });

    Lifter lift = [=](Observable input) {
        return input.filter(opBuilderHelperStringEqN(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
}

// Test ok: dynamic values (string)
TEST(opBuilderHelperStringEqN, ReferencedString)
{
    Document doc {R"({
        "check":
            {"sourceField": "+s_eq_n/10/$ref_key"}
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                    "sourceField":"not_test_value",
                    "ref_key":"test_value"
                }
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {
                    "sourceField":"test_value",
                    "ref_key":"test_value"
                }
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {
                    "otherfield":"value",
                    "ref_key":"test_value"
                }
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {
                    "otherfield":"test_value",
                    "ref_key":"test_value"
                }
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {
                    "sourceField":"test_value_extended",
                    "ref_key":"test_value_extra_extended"
                }
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {
                    "sourceField":"test_value_extra_extended",
                    "ref_key":"test_value_extended"
                } // Shall pass
            )"));
        s.on_completed();
    });

    Lifter lift = [=](Observable input) {
        return input.filter(opBuilderHelperStringEqN(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
}

// Test ok: multilevel referenced values (string)
TEST(opBuilderHelperStringEqN, NestedReferencedStrings)
{
    Document doc {R"({
        "check":
            {"rootKey1.sourceField": "+s_eq_n/1/$rootKey2.ref_key"}
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                    "rootKey2": {
                        "sourceField": "test_value",
                        "ref_key": "test_value"
                    },
                    "rootKey1": {
                        "sourceField": "sample_value",
                        "ref_key": "sample_value"
                    }
                }
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {
                    "parentObjt_2": {
                        "sourceField": "test_value",
                        "ref_key": "sample_value"
                    },
                    "parentObjt_1": {
                        "sourceField": "sample_value",
                        "ref_key": "test_value"
                    }
                }
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {
                    "parentObjt_2": {
                        "sourceField": "test_value_extended",
                        "ref_key": "sample_value"
                    },
                    "parentObjt_1": {
                        "sourceField": "sample_value",
                        "ref_key": "test_value"
                    }
                }
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {
                    "parentObjt_2": {
                        "sourceField": "test_value_extended",
                        "ref_key": "sample_value"
                    },
                    "parentObjt_1": {
                        "sourceField": "sample_value",
                        "ref_key": "test_value_extra_extended"
                    }
                }
            )")); // Shall pass
        s.on_completed();
    });

    Lifter lift = [=](Observable input) {
        return input.filter(opBuilderHelperStringEqN(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
}

// Test ok: multilevel referenced values (int)
TEST(opBuilderHelperStringEqN, NestedReferencedStrings)
{
    Document doc {R"({
        "check":
            {"rootKey1.sourceField": "+s_eq_n/1/$rootKey2.ref_key"}
    })"};

    Observable input = observable<>::create<Event>([=](auto s) {
        s.on_next(createSharedEvent(R"(
                {
                    "rootKey2": {
                        "sourceField": 404,
                        "ref_key": 404
                    },
                    "rootKey1": {
                        "sourceField": 911,
                        "ref_key": 911
                    }
                }
            )")); // Shall not pass
        s.on_next(createSharedEvent(R"(
                {
                    "parentObjt_2": {
                        "sourceField": 404,
                        "ref_key": 911
                    },
                    "parentObjt_1": {
                        "sourceField": 911,
                        "ref_key": 404
                    }
                }
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {
                    "parentObjt_2": {
                        "sourceField": 404666,
                        "ref_key": 911
                    },
                    "parentObjt_1": {
                        "sourceField": 911,
                        "ref_key": 404
                    }
                }
            )")); // Shall pass
        s.on_next(createSharedEvent(R"(
                {
                    "parentObjt_2": {
                        "sourceField": 404666,
                        "ref_key": 911
                    },
                    "parentObjt_1": {
                        "sourceField": 911,
                        "ref_key": 404123321
                    }
                }
            )")); // Shall pass
        s.on_completed();
    });

    Lifter lift = [=](Observable input) {
        return input.filter(opBuilderHelperStringEqN(doc.get("/check"), tr));
    };
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 3);
}
