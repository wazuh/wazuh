#include <gtest/gtest.h>

#include "hlp_test.hpp"

auto constexpr NAME = "jsonParser";
static const std::string TARGET = "/TargetField";

INSTANTIATE_TEST_SUITE_P(JSONBuild,
                         HlpBuildTest,
                         ::testing::Values(BuildT(SUCCESS, getJSONParser, {NAME, TARGET, {}, {}}),
                                           BuildT(FAILURE, getJSONParser, {NAME, TARGET, {}, {"unexpected"}})));

INSTANTIATE_TEST_SUITE_P(
    JSONParse,
    HlpParseTest,
    ::testing::Values(
        ParseT(SUCCESS, "{}", j(fmt::format(R"({{"{}":{{}}}})", TARGET.substr(1))), 2, getJSONParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "{}left over",
               j(fmt::format(R"({{"{}":{{}}}})", TARGET.substr(1))),
               2,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "null", j(fmt::format(R"({{"{}":null}})", TARGET.substr(1))), 4, getJSONParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "nullleft over",
               j(fmt::format(R"({{"{}":null}})", TARGET.substr(1))),
               4,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "true", j(fmt::format(R"({{"{}":true}})", TARGET.substr(1))), 4, getJSONParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "trueleft over",
               j(fmt::format(R"({{"{}":true}})", TARGET.substr(1))),
               4,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "false", j(fmt::format(R"({{"{}":false}})", TARGET.substr(1))), 5, getJSONParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "falseleft over",
               j(fmt::format(R"({{"{}":false}})", TARGET.substr(1))),
               5,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "123", j(fmt::format(R"({{"{}":123}})", TARGET.substr(1))), 3, getJSONParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "123left over",
               j(fmt::format(R"({{"{}":123}})", TARGET.substr(1))),
               3,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               "123.456",
               j(fmt::format(R"({{"{}":123.456}})", TARGET.substr(1))),
               7,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        // This should pass
        // TODO: this fails on rapidjson parser
        // ParseT(SUCCESS,
        //        "123.456left over",
        //        j(fmt::format(R"({{"{}":123.456}})", TARGET.substr(1))),
        //        7,
        //        getJSONParser,
        //        {NAME, TARGET, {}, {}}),
        ParseT(
            SUCCESS, R"("abc")", j(fmt::format(R"({{"{}":"abc"}})", TARGET.substr(1))), 5, getJSONParser, {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS,
               R"("abc"left over)",
               j(fmt::format(R"({{"{}":"abc"}})", TARGET.substr(1))),
               5,
               getJSONParser,
               {NAME, TARGET, {}, {}}),
        ParseT(SUCCESS, "[]", j(fmt::format(R"({{"{}":[]}})", TARGET.substr(1))), 2, getJSONParser, {NAME, TARGET, {}, {}}),
        ParseT(
            SUCCESS, "[]left over", j(fmt::format(R"({{"{}":[]}})", TARGET.substr(1))), 2, getJSONParser, {NAME, TARGET, {}, {}}),
        ParseT(
            SUCCESS,
            R"({"Actors":[{"name":"Tom Cruise","age":56,"Born At":"Syracuse, NY","Birthdate":"July 3, 1962","photo":"https://jsonformatterdotorg/img/tom-cruise.jpg","wife":null,"weight":67.5,"hasChildren":true,"hasGreyHair":false,"children":["Suri","Isabella Jane","Connor"]},{"name":"Robert Downey Jr.","age":53,"Born At":"New York City, NY","Birthdate":"April 4, 1965","photo":"https://jsonformatterdotorg/img/Robert-Downey-Jr.jpg","wife":"Susan Downey","weight":77.1,"hasChildren":true,"hasGreyHair":false,"children":["Indio Falconer","Avri Roel","Exton Elias"]}]})",
            j(fmt::format(
                R"({{"{}":{} }})",
                TARGET.substr(1),
                R"({"Actors":[{"name":"Tom Cruise","age":56,"Born At":"Syracuse, NY","Birthdate":"July 3, 1962","photo":"https://jsonformatterdotorg/img/tom-cruise.jpg","wife":null,"weight":67.5,"hasChildren":true,"hasGreyHair":false,"children":["Suri","Isabella Jane","Connor"]},{"name":"Robert Downey Jr.","age":53,"Born At":"New York City, NY","Birthdate":"April 4, 1965","photo":"https://jsonformatterdotorg/img/Robert-Downey-Jr.jpg","wife":"Susan Downey","weight":77.1,"hasChildren":true,"hasGreyHair":false,"children":["Indio Falconer","Avri Roel","Exton Elias"]}]})")),
            552,
            getJSONParser,
            {NAME, TARGET, {}, {}})));
