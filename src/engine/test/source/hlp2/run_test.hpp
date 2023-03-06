#ifndef RUNTEST
#define RUNTEST
#include <gtest/gtest.h>

#include <functional>
#include <list>
#include <optional>

#include <fmt/format.h>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

#define GTEST_COUT std::cerr << "[          ] [ DEBUG ] "

using namespace hlp;

// A TestCase is a tuple of
//   [0] std::string input to parse,
//   [1] bool to know if the parsing was succesful
//   [2] std::optional<std::string> optional stop string,
//   [3] std::list<std::string> options,
//   [4] std::string which will be inside the json::Json returned value,
//   [5] int index position
using TestCase = std::tuple<std::string, bool, Stop, Options, json::Json, size_t>;

namespace
{

// Print a stop as a string
std::string printStop(const Stop& stop)
{
    std::string res = fmt::format("{}", fmt::join(stop, ", "));
    return res;
}
// Print a list of options as a string
std::string printOptions(const Options& options)
{
    std::string res = fmt::format("{}", fmt::join(options, ", "));
    return res;
}

// Print a TestCase to a std::string
std::string to_string(const TestCase& testCase)
{
    auto [input, success, stop, options, doc, index] = testCase;
    return fmt::format("TestCase: \ninput: {}\n success: {}\n stop: {}\n options: "
                       "{}\n doc: {}\n index: {}\n",
                       input,
                       success,
                       printStop(stop),
                       printOptions(options),
                       doc.str(),
                       index);
}
} // namespace

/**
 * @brief Builds and runs a test case. The execution is repeated four times adding different combinations of header and
 * tail to the input string to be parsed
 *
 * @param t The tuple containing the test case parameters
 * @param parserBuilder The parser builder
 * @header The header to be appended to the input string
 * @tail The tail to be appended to the input string
 * @strictStop The end token is not modified and no tail is added
 */
static void runTest(TestCase t,
                    std::function<parsec::Parser<json::Json>(std::string, Stop, Options)> parserBuilder,
                    const std::string& header = "header ",
                    const std::string& tail = " tail",
                    bool strictStop = false)
{
    parsec::Parser<json::Json> parser;
    auto expectedSuccess = std::get<1>(t);
    auto expectedDoc = std::get<4>(t);

    std::string token[4][2] = {{"", ""}, {header, ""}, {"", tail}, {header, tail}};

    for (int i = 0; i < 4; i++)
    {
        auto stopString = printStop(std::get<2>(t));
        std::list<std::string> tokenList = {token[i][1]};
        std::list<std::string> stopStringList = (strictStop || !stopString.empty()) ? std::get<2>(t) : tokenList;
        try
        {
            parser = parserBuilder({}, stopStringList, std::get<3>(t));
        }
        catch (std::runtime_error& e)
        {
            ASSERT_FALSE(expectedSuccess)
                << fmt::format("Error building parser: {}", e.what());
            return;
        }
        auto fullEvent = token[i][0] + std::get<0>(t) + (strictStop ? "" : token[i][1]);
        auto r = parser(fullEvent, token[i][0].size());

        ASSERT_EQ(r.success(), expectedSuccess)
            << (r.success() ? "" : "ParserError: " + r.error() + "\n") << to_string(t);
        if (r.success())
        {
            ASSERT_EQ(expectedDoc, r.value()) << to_string(t);
            ASSERT_EQ(r.index() - token[i][0].size(), std::get<5>(t)) << to_string(t);
        }
        else
        {
            ASSERT_FALSE(r.error().empty());
        }
    }
}
#endif // WAZUH_ENGINE_HLP_H
