/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <gtest/gtest.h>
#include <testUtils.hpp>

#include <vector>

#include "OpBuilderHelperMap.hpp"

using namespace builder::internals::builders;

TEST(opBuilderHelperIntCalc, Builds)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/+/10"}
    })"};
    ASSERT_NO_THROW(opBuilderHelperIntCalc(*doc.get("/check")));
}

TEST(opBuilderHelperIntCalc, Builds_error_bad_parameter)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/test/test"}
    })"};
    ASSERT_THROW(opBuilderHelperIntCalc(*doc.get("/check")), std::runtime_error);
}

TEST(opBuilderHelperIntCalc, Builds_error_less_parameters)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/10"}
    })"};
    ASSERT_THROW(opBuilderHelperIntCalc(*doc.get("/check")), std::runtime_error);
}


TEST(opBuilderHelperIntCalc, Builds_error_more_parameters)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/10/10/10"}
    })"};
    ASSERT_THROW(opBuilderHelperIntCalc(*doc.get("/check")), std::runtime_error);
}

TEST(opBuilderHelperIntCalc, Builds_error_bad_operator)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/^/10"}
    })"};
    ASSERT_THROW(opBuilderHelperIntCalc(*doc.get("/check")), std::runtime_error);
}

//TODO test division by zero
TEST(opBuilderHelperIntCalc, Builds_error_zero_division)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/%/0"}
    })"};
    ASSERT_THROW(opBuilderHelperIntCalc(*doc.get("/check")), std::runtime_error);
}

TEST(opBuilderHelperIntCalc, Exec_equal_ok)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/+/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test":9}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 4);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),19);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),20);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),20);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),21);

}

TEST(opBuilderHelperIntCalc, Exec_sum_int)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/+/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test":0}
            )"});
            s.on_next(Event{R"(
                {"field_test":9}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11}
            )"});
            s.on_next(Event{R"(
                {"field_test":100}
            )"});
            s.on_next(Event{R"(
                {"field_test":-100}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 6);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),10);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),19);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),20);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),21);
    ASSERT_EQ(expected[4].get("/field_test")->GetInt(),110);
    ASSERT_EQ(expected[5].get("/field_test")->GetInt(),-90);

}

TEST(opBuilderHelperIntCalc, Exec_sub_int)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/-/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test":0}
            )"});
            s.on_next(Event{R"(
                {"field_test":9}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11}
            )"});
            s.on_next(Event{R"(
                {"field_test":100}
            )"});
            s.on_next(Event{R"(
                {"field_test":-100}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 6);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),-10);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),-1);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),1);
    ASSERT_EQ(expected[4].get("/field_test")->GetInt(),90);
    ASSERT_EQ(expected[5].get("/field_test")->GetInt(),-110);

}

TEST(opBuilderHelperIntCalc, Exec_mult_int)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/*/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test":0}
            )"});
            s.on_next(Event{R"(
                {"field_test":9}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11}
            )"});
            s.on_next(Event{R"(
                {"field_test":100}
            )"});
            s.on_next(Event{R"(
                {"field_test":-100}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 6);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),90);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),100);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),110);
    ASSERT_EQ(expected[4].get("/field_test")->GetInt(),1000);
    ASSERT_EQ(expected[5].get("/field_test")->GetInt(),-1000);

}

TEST(opBuilderHelperIntCalc, Exec_div_int)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/%/10"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test":0}
            )"});
            s.on_next(Event{R"(
                {"field_test":9}
            )"});
            s.on_next(Event{R"(
                {"field_test":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11}
            )"});
            s.on_next(Event{R"(
                {"field_test":100}
            )"});
            s.on_next(Event{R"(
                {"field_test":-100}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });
    ASSERT_EQ(expected.size(), 6);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),1);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),1);
    ASSERT_EQ(expected[4].get("/field_test")->GetInt(),10);
    ASSERT_EQ(expected[5].get("/field_test")->GetInt(),-10);

}

TEST(opBuilderHelperIntCalc, Exec_sum_ref)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/+/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":-10}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    auto str2Int = [](std::string s) {
        return std::stoi(s);
    };

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),10);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),19);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),20);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),21);
    ASSERT_EQ(expected[4].get("/field_test")->GetInt(),-10);
    ASSERT_EQ(expected[5].get("/field_test")->GetInt(),-1);
    ASSERT_EQ(expected[6].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[7].get("/field_test")->GetInt(),1);

}

TEST(opBuilderHelperIntCalc, Exec_sub_ref)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/-/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":-10}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    auto str2Int = [](std::string s) {
        return std::stoi(s);
    };

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),-10);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),-1);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),1);
    ASSERT_EQ(expected[4].get("/field_test")->GetInt(),10);
    ASSERT_EQ(expected[5].get("/field_test")->GetInt(),19);
    ASSERT_EQ(expected[6].get("/field_test")->GetInt(),20);
    ASSERT_EQ(expected[7].get("/field_test")->GetInt(),21);

}

TEST(opBuilderHelperIntCalc, Exec_mult_ref)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/*/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":-10}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    auto str2Int = [](std::string s) {
        return std::stoi(s);
    };

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),90);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),100);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),110);
    ASSERT_EQ(expected[4].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[5].get("/field_test")->GetInt(),-90);
    ASSERT_EQ(expected[6].get("/field_test")->GetInt(),-100);
    ASSERT_EQ(expected[7].get("/field_test")->GetInt(),-110);

}

TEST(opBuilderHelperIntCalc, Exec_div_ref)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/%/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":-10}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":-10}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    auto str2Int = [](std::string s) {
        return std::stoi(s);
    };

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),1);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),1);
    ASSERT_EQ(expected[4].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[5].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[6].get("/field_test")->GetInt(),-1);
    ASSERT_EQ(expected[7].get("/field_test")->GetInt(),-1);

}

TEST(opBuilderHelperIntCalc, Exec_div_ref_zero)
{
    Document doc{R"({
        "check":
            {"field_test": "+i_calc/%/$field_src"}
    })"};

    Observable input = observable<>::create<Event>(
        [=](auto s)
        {
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":0}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":0}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":0}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":0}
            )"});
            s.on_next(Event{R"(
                {"field_test": 0,"field_src":0}
            )"});
            s.on_next(Event{R"(
                {"field_test":9,"field_src":0}
            )"});
            s.on_next(Event{R"(
                {"field_test": 10,"field_src":0}
            )"});
            s.on_next(Event{R"(
                {"field_test":11,"field_src":0}
            )"});
            s.on_completed();
        });
    Lifter lift = opBuilderHelperIntCalc(*doc.get("/check"));
    Observable output = lift(input);
    vector<Event> expected;
    output.subscribe([&](Event e) { expected.push_back(e); });

    auto str2Int = [](std::string s) {
        return std::stoi(s);
    };

    ASSERT_EQ(expected.size(), 8);
    ASSERT_EQ(expected[0].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[1].get("/field_test")->GetInt(),9);
    ASSERT_EQ(expected[2].get("/field_test")->GetInt(),10);
    ASSERT_EQ(expected[3].get("/field_test")->GetInt(),11);
    ASSERT_EQ(expected[4].get("/field_test")->GetInt(),0);
    ASSERT_EQ(expected[5].get("/field_test")->GetInt(),9);
    ASSERT_EQ(expected[6].get("/field_test")->GetInt(),10);
    ASSERT_EQ(expected[7].get("/field_test")->GetInt(),11);

}
