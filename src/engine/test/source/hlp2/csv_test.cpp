#include <gtest/gtest.h>
#include <hlp/hlp.hpp>
#include <optional>
#include <string>
#include <vector>
#include "run_test.hpp"

TEST(HLP2, CSVParser)
{
    auto fn = [](std::string in) -> json::Json {
        json::Json doc;
        try {
        doc = json::Json(in.c_str());
        } catch ( std::exception & e) {
            std::cout << "AQUI!! "<< std::endl;
        }
        return doc;
    };

    std::vector<TestCase> testCases {
        TestCase {"val1,val2,val3,val4",  true, {},Options{"f1","f2","f3","f4" },fn(R"({"f1":"val1","f2":"val2","f3":"val3","f4":"val4"}))"), 0},
        TestCase {"invalid string",  false,{},Options{"f1","f2","f3","f4" }, fn(R"({"f1":"val1","f2":"val2","f3":"val3","f4":"val4"})"), 12},
    };


    for (auto t : testCases)
    {
        runTest(t, hlp::getCSVParser);
    }
}
