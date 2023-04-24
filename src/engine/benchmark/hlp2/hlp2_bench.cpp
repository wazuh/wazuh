#include <string>
#include <iostream>

#include <benchmark/benchmark.h>

#include <hlp/hlp.hpp>
#include <hlp/logpar.hpp>
#include <json/json.hpp>



static std::string getRandomString(int len,
                                   bool includeSymbols = false,
                                   bool onlyNumbers = false,
                                   bool withFloatingPoint = false)
{
    static const char numbers[] = "0123456789";
    static const char alphanum[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                                   "abcdefghijklmnopqrstuvwxyz";

    static const char symbols[] = "-_'\\/. *!\"#$%&()+[]{},;";

    std::string tmp_s;
    int floating_point_position;
    tmp_s.reserve(len);

    std::string dict = numbers;
    if (!onlyNumbers)
    {
        dict += alphanum;
    }
    else if (withFloatingPoint)
    {
        floating_point_position = rand() % len;
    }

    if (includeSymbols)
    {
        dict += symbols;
    }

    for (int i = 0; i < len; ++i)
    {
        if (onlyNumbers && withFloatingPoint && (i == floating_point_position))
        {
            tmp_s += ".";
        }
        else
        {
            tmp_s += dict[rand() % dict.size()];
        }
    }
    return tmp_s;
}

namespace logpar_bench
{
json::Json getConfig()
{
    json::Json config {};
    config.setObject();
    config.setString(hlp::schemaTypeToStr(hlp::SchemaType::LONG), "/fields/int");
    config.setString(hlp::schemaTypeToStr(hlp::SchemaType::TEXT), "/fields/ip");
    return config;
}

hlp::logpar::Logpar getLogpar()
{
    hlp::logpar::Logpar ret {getConfig()};
    ret.registerBuilder(hlp::ParserType::P_LONG, hlp::getLongParser); // Number
    ret.registerBuilder(hlp::ParserType::P_TEXT, hlp::getTextParser); // Any
    ret.registerBuilder(hlp::ParserType::P_QUOTED, hlp::getQuotedParser);
    ret.registerBuilder(hlp::ParserType::P_IP, hlp::getIPParser);
    ret.registerBuilder(hlp::ParserType::P_LITERAL, hlp::getLiteralParser);
    return ret;
}

} // namespace logpar_bench

static void logpar_parse(benchmark::State& state)
{
    auto logpar = logpar_bench::getLogpar();
    std::string parserStr {};

    // std::string parserStr = "hola<~srcip/ip>:<~port/long><~quoted/quoted>";
    // std::string ev = "hola127.0.0.1:8080\"quoted\"";

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    parserStr += ev1;

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    /*
    try
    {
        auto parser = logpar.build(parserStr);
        auto result = parser(ev, 0);
        if (result.success())
        {
            std::cout << result.value().prettyStr() << std::endl;
        }
    }
    catch (std::exception& e)
    {
        std::cout << e.what() << std::endl;
        state.SkipWithError(e.what());
    }
    */

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    for (auto _ : state)
    {
        auto result = parser(ev, 0);
        if (result.failure())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

    // auto result = parser(ev, 0);
    // std::cout << result.value().str() << std::endl;
}
BENCHMARK(logpar_parse)->Range(4, 4 << 4);



static void logpar_parse_error_IP_1(benchmark::State& state)
{
    auto logpar = logpar_bench::getLogpar();
    std::string parserStr {};

    // std::string parserStr = "hola<~srcip/ip>:<~port/long><~quoted/quoted>";
    // std::string ev = "hola127.0.0.1:8080\"quoted\"";

    // Error
    parserStr += "<~srcip/ip>:";

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    parserStr += ev1;

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";


    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    for (auto _ : state)
    {
        auto result = parser(ev, 0);
        if (result.success())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

}
BENCHMARK(logpar_parse_error_IP_1)->Range(4, 4 << 4);


static void logpar_parse_error_IP_2(benchmark::State& state)
{
    auto logpar = logpar_bench::getLogpar();
    std::string parserStr {};

    // std::string parserStr = "hola<~srcip/ip>:<~port/long><~quoted/quoted>";
    // std::string ev = "hola127.0.0.1:8080\"quoted\"";

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    parserStr += ev1;


    // Error
    parserStr += "<~srcip/ip>:";

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";


    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    for (auto _ : state)
    {
        auto result = parser(ev, 0);
        if (result.success())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

}
BENCHMARK(logpar_parse_error_IP_2)->Range(4, 4 << 4);


static void logpar_parse_error_IP_3(benchmark::State& state)
{
    auto logpar = logpar_bench::getLogpar();
    std::string parserStr {};

    // std::string parserStr = "hola<~srcip/ip>:<~port/long><~quoted/quoted>";
    // std::string ev = "hola127.0.0.1:8080\"quoted\"";

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    parserStr += ev1;

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";

    // Error
    parserStr += "<~srcip/ip>:";

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    for (auto _ : state)
    {
        auto result = parser(ev, 0);
        if (result.success())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

}
BENCHMARK(logpar_parse_error_IP_3)->Range(4, 4 << 4);


static void logpar_parse_error_IP_4(benchmark::State& state)
{
    auto logpar = logpar_bench::getLogpar();
    std::string parserStr {};

    // std::string parserStr = "hola<~srcip/ip>:<~port/long><~quoted/quoted>";
    // std::string ev = "hola127.0.0.1:8080\"quoted\"";

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    parserStr += ev1;

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    // Error
    parserStr += "<~srcip/ip>:";

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    for (auto _ : state)
    {
        auto result = parser(ev, 0);
        if (result.success())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

}
BENCHMARK(logpar_parse_error_IP_4)->Range(4, 4 << 4);
/*****************************************************************/



static void logpar_parse_error_LIT_1(benchmark::State& state)
{
    auto logpar = logpar_bench::getLogpar();
    std::string parserStr {};

    // std::string parserStr = "hola<~srcip/ip>:<~port/long><~quoted/quoted>";
    // std::string ev = "hola127.0.0.1:8080\"quoted\"";

    // Error
    parserStr += "........";

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    parserStr += ev1;

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";


    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    for (auto _ : state)
    {
        auto result = parser(ev, 0);
        if (result.success())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

}
BENCHMARK(logpar_parse_error_LIT_1)->Range(4, 4 << 4);


static void logpar_parse_error_LIT_2(benchmark::State& state)
{
    auto logpar = logpar_bench::getLogpar();
    std::string parserStr {};

    // std::string parserStr = "hola<~srcip/ip>:<~port/long><~quoted/quoted>";
    // std::string ev = "hola127.0.0.1:8080\"quoted\"";

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    parserStr += ev1;


    // Error
    parserStr += "........";

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";


    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    for (auto _ : state)
    {
        auto result = parser(ev, 0);
        if (result.success())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

}
BENCHMARK(logpar_parse_error_LIT_2)->Range(4, 4 << 4);


static void logpar_parse_error_LIT_3(benchmark::State& state)
{
    auto logpar = logpar_bench::getLogpar();
    std::string parserStr {};

    // std::string parserStr = "hola<~srcip/ip>:<~port/long><~quoted/quoted>";
    // std::string ev = "hola127.0.0.1:8080\"quoted\"";

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    parserStr += ev1;

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";

    // Error
    parserStr += "........";

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    for (auto _ : state)
    {
        auto result = parser(ev, 0);
        if (result.success())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

}
BENCHMARK(logpar_parse_error_LIT_3)->Range(4, 4 << 4);


static void logpar_parse_error_LIT_4(benchmark::State& state)
{
    auto logpar = logpar_bench::getLogpar();
    std::string parserStr {};

    // std::string parserStr = "hola<~srcip/ip>:<~port/long><~quoted/quoted>";
    // std::string ev = "hola127.0.0.1:8080\"quoted\"";

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    parserStr += ev1;

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    // Error
    parserStr += "........";

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    for (auto _ : state)
    {
        auto result = parser(ev, 0);
        if (result.success())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

}
BENCHMARK(logpar_parse_error_LIT_4)->Range(4, 4 << 4);
