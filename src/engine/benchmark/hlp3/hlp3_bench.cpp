#include <string>
#include <iostream>

#include <benchmark/benchmark.h>
#include <hlp3/hlp3.hpp>

using namespace hlp3::parser;



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

static void any_string_variable_length_parse(benchmark::State& state)
{
    std::string ev = getRandomString(state.range(0));

    auto parserAny = getParserAny("/test", "", false, false);
    InputP input = InputP(ev.c_str());
    fnList resultFn {};

    for (auto _ : state)
    {
        auto sintaticResult = parserAny(input);
        if (!sintaticResult) {
            state.SkipWithError("sintatic failed");
        }
        auto result = sintaticResult.popValue().value();
        auto [success, trace] = result.m_semanticProcessor(resultFn, result.m_tokens);
        if (!success) {
            state.SkipWithError("Semantic failed");
        }
    }
}
BENCHMARK(any_string_variable_length_parse)->Range(8, 8 << 8);

static void any_string_variable_length_parse_merged(benchmark::State& state)
{
    std::string ev = getRandomString(state.range(0));
    ev += "EndToken";

    auto parserAny = getParserAny("/test", "EndToken", false, false);
    InputP input = InputP(ev.c_str());
    fnList resultFn {};

    auto list = std::list<combinator::MergeableParser<fnList>>{parserAny};
    auto merged = combinator::merge(list);

    for (auto _ : state)
    {
        if (!merged(input)) {
            state.SkipWithError("sintatic failed");
        }

    }
}
BENCHMARK(any_string_variable_length_parse_merged)->Range(8, 8 << 8);


static void ipv4_parse(benchmark::State& state)
{
    std::string ev = "127.0.0.1";

    auto parserIpv4 = getParserIP("/test", "", true, false);
    InputP input = InputP(ev.c_str());
    fnList resultFn {};


    for (auto _ : state)
    {
        auto sintaticResult = parserIpv4(input);
        if (!sintaticResult) {
            state.SkipWithError("sintatic failed");
        }
        auto result = sintaticResult.popValue().value();
        auto [success, trace] = result.m_semanticProcessor(resultFn, result.m_tokens);
        if (!success) {
            state.SkipWithError("Semantic failed");
        }
    }
}
BENCHMARK(ipv4_parse);

static void ipv4_parse_merged(benchmark::State& state)
{
    std::string ev = "127.0.0.1";

    auto parserIpv4 = getParserIP("/test", "", true, false);
    InputP input = InputP(ev.c_str());

    auto list = std::list<combinator::MergeableParser<fnList>>{parserIpv4};
    auto merged = combinator::merge(list);

    for (auto _ : state)
    {
        if (!merged(input)) {
            state.SkipWithError("sintatic failed");
        }
    }
}
BENCHMARK(ipv4_parse_merged);


static void match_literal_range(benchmark::State& state)
{
    srand((unsigned)time(NULL));
    std::string ev = getRandomString(state.range(0));

    auto parserAny = getParseLiteral("/test", ev, false, false);
    InputP input = InputP(ev.c_str());

    fnList resultFn {};

    for (auto _ : state)
    {
        auto sintaticResult = parserAny(input);
        if (!sintaticResult) {
            state.SkipWithError("sintatic failed");
        }
        auto result = sintaticResult.popValue().value();
        auto [success, trace] = result.m_semanticProcessor(resultFn, result.m_tokens);
        if (!success) {
            state.SkipWithError("Semantic failed");
        }
    }
}
BENCHMARK(match_literal_range)->Range(8, 8 << 11);

static void match_literal_range_merged(benchmark::State& state)
{
    srand((unsigned)time(NULL));
    std::string ev = getRandomString(state.range(0));

    auto parserAny = getParseLiteral("/test", ev, false, false);
    InputP input = InputP(ev.c_str());

    auto list = std::list<combinator::MergeableParser<fnList>>{parserAny};
    auto merged = combinator::merge(list);

    for (auto _ : state)
    {
        if (!merged(input)) {
            state.SkipWithError("sintatic failed");
        }
    }
}
BENCHMARK(match_literal_range_merged)->Range(8, 8 << 11);


static void integer_number_variable_length_parse(benchmark::State& state)
{
    std::string ev = getRandomString(state.range(0), false, true);

    auto parserNumber = getParseNumber("/test", true, false);
    InputP input = InputP(ev.c_str());


    fnList resultFn {};

    for (auto _ : state)
    {
        auto sintaticResult = parserNumber(input);
        if (!sintaticResult) {
            state.SkipWithError("sintatic failed");
        }
        auto result = sintaticResult.popValue().value();
        auto [success, trace] = result.m_semanticProcessor(resultFn, result.m_tokens);
        if (!success) {
            state.SkipWithError("Semantic failed");
        }
    }
}
BENCHMARK(integer_number_variable_length_parse)->Range(8, 18);

static void integer_number_variable_length_parse_merged(benchmark::State& state)
{
    std::string ev = getRandomString(state.range(0), false, true);

    auto parserNumber = getParseNumber("/test", true, false);
    InputP input = InputP(ev.c_str());

    auto list = std::list<combinator::MergeableParser<fnList>>{parserNumber};
    auto merged = combinator::merge(list);

    for (auto _ : state)
    {
        if (!merged(input)) {
            state.SkipWithError("sintatic failed");
        }
    }
}

static void quoted_string_variable_length_parse(benchmark::State& state)
{
    std::string ev = "\"" + getRandomString(state.range(0)) + "\"";

    auto parserQuoted = getParseQuotedString("/test", true, false);
    InputP input = InputP(ev.c_str());

    fnList resultFn {};

    for (auto _ : state)
    {
        auto sintaticResult = parserQuoted(input);
        if (!sintaticResult) {
            state.SkipWithError("sintatic failed");
        }
        auto result = sintaticResult.popValue().value();
        auto [success, trace] = result.m_semanticProcessor(resultFn, result.m_tokens);
        if (!success) {
            state.SkipWithError("Semantic failed");
        }
    }


}
BENCHMARK(quoted_string_variable_length_parse)->Range(8, 8 << 8);

static void quoted_string_variable_length_parse_merged(benchmark::State& state)
{
    std::string ev = "\"" + getRandomString(state.range(0)) + "\"";

    auto parserQuoted = getParseQuotedString("/test", true, false);
    InputP input = InputP(ev.c_str());

    auto list = std::list<combinator::MergeableParser<fnList>>{parserQuoted};
    auto merged = combinator::merge(list);

    for (auto _ : state)
    {
        if (!merged(input)) {
            state.SkipWithError("sintatic failed");
        }
    }
}BENCHMARK(quoted_string_variable_length_parse_merged)->Range(8, 8 << 8);


// Merged combinators
static void merged_combinators(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        parseLiteral_ev1,
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        parserQuoted_ev3
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());

    for (auto _ : state)
    {
        if (!merged(input)) {
            state.SkipWithError("Parsing failed");
        }
    }

    auto result = merged(input).popValue().value();
    json::Json jsonRes {};

    for (auto& fn : result) {
        fn(jsonRes);
    }

    // std::cout << jsonRes.str() << std::endl;

}BENCHMARK(merged_combinators)->Range(4, 4 << 4);


// Merged combinators
static void merged_combinators_and_push(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        parseLiteral_ev1,
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        parserQuoted_ev3
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());
    json::Json jsonRes {};

    for (auto _ : state)
    {
        auto result = merged(input);
        if (!result) {
            state.SkipWithError("Parsing failed");
        }
        auto listFn = result.popValue().value();
        for (auto& fn : listFn)
        {
            fn(jsonRes);
        }
        benchmark::DoNotOptimize(result);
    }

    // std::cout << jsonRes.str() << std::endl;

}BENCHMARK(merged_combinators_and_push)->Range(4, 4 << 4);



// Merged combinators
static void merged_combinators_error_ip(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        getParserIP("srcip2", R"(:)", true, false),
        parseLiteral_ev1,
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        parserQuoted_ev3
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());
    json::Json jsonRes {};

    for (auto _ : state)
    {
        auto result = merged(input);
        if (result) {
            auto listFn = result.popValue().value();
            for (auto& fn : listFn)
            {
                fn(jsonRes);
            }
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);

    }

}BENCHMARK(merged_combinators_error_ip)->Range(4, 4 << 4);


// Merged combinators
static void merged_combinators_error_ip_2(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        parseLiteral_ev1,
        getParserIP("srcip2", R"(:)", true, false),
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        parserQuoted_ev3
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());
    json::Json jsonRes {};

    for (auto _ : state)
    {
        auto result = merged(input);
        if (result) {
            auto listFn = result.popValue().value();
            for (auto& fn : listFn)
            {
                fn(jsonRes);
            }
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);

    }

}BENCHMARK(merged_combinators_error_ip_2)->Range(4, 4 << 4);


// Merged combinators
static void merged_combinators_error_ip_3(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        parseLiteral_ev1,
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        getParserIP("srcip2", R"(:)", true, false),
        parserQuoted_ev3
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());
    json::Json jsonRes {};

    for (auto _ : state)
    {
        auto result = merged(input);
        if (result) {
            auto listFn = result.popValue().value();
            for (auto& fn : listFn)
            {
                fn(jsonRes);
            }
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);

    }

}BENCHMARK(merged_combinators_error_ip_3)->Range(4, 4 << 4);


// Merged combinators
static void merged_combinators_error_ip_4(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        parseLiteral_ev1,
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        parserQuoted_ev3,
        getParserIP("srcip2", R"(:)", true, false),
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());
    json::Json jsonRes {};

    for (auto _ : state)
    {
        auto result = merged(input);
        if (result) {
            auto listFn = result.popValue().value();
            for (auto& fn : listFn)
            {
                fn(jsonRes);
            }
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);

    }


}BENCHMARK(merged_combinators_error_ip_4)->Range(4, 4 << 4);
/************************************************/


// Merged combinators
static void merged_combinators_error_lit(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        getParseLiteral("srcip2", R"(........)", false, false),
        parseLiteral_ev1,
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        parserQuoted_ev3
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());
    json::Json jsonRes {};

    for (auto _ : state)
    {
        auto result = merged(input);
        if (result) {
            auto listFn = result.popValue().value();
            for (auto& fn : listFn)
            {
                fn(jsonRes);
            }
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);

    }

}BENCHMARK(merged_combinators_error_lit)->Range(4, 4 << 4);


// Merged combinators
static void merged_combinators_error_lit_2(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        parseLiteral_ev1,
        getParseLiteral("srcip2", R"(........)", false, false),
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        parserQuoted_ev3
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());
    json::Json jsonRes {};

    for (auto _ : state)
    {
        auto result = merged(input);
        if (result) {
            auto listFn = result.popValue().value();
            for (auto& fn : listFn)
            {
                fn(jsonRes);
            }
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);

    }

}BENCHMARK(merged_combinators_error_lit_2)->Range(4, 4 << 4);


// Merged combinators
static void merged_combinators_error_lit_3(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        parseLiteral_ev1,
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        getParseLiteral("srcip2", R"(........)", false, false),
        parserQuoted_ev3
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());
    json::Json jsonRes {};

    for (auto _ : state)
    {
        auto result = merged(input);
        if (result) {
            auto listFn = result.popValue().value();
            for (auto& fn : listFn)
            {
                fn(jsonRes);
            }
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);

    }

}BENCHMARK(merged_combinators_error_lit_3)->Range(4, 4 << 4);


// Merged combinators
static void merged_combinators_error_lit_4(benchmark::State& state)
{

    // Literal
    std::string ev1 = getRandomString(state.range(0));
    auto parseLiteral_ev1 = getParseLiteral("literal", ev1, false, false);

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    auto parserIP_ev2 = getParserIP("srcip", R"(:)", true, false);
    auto parseLiteral3_ev2 = getParseLiteral("literal", ":", false, false);
    auto parserNumber_ev2 = getParseNumber("port", true, false);

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    auto parserQuoted_ev3 = getParseQuotedString("quoted", true, false);

    // Merge
    auto list = std::list<combinator::MergeableParser<fnList>>{
        parseLiteral_ev1,
        parserIP_ev2,
        parseLiteral3_ev2,
        parserNumber_ev2,
        parserQuoted_ev3,
        getParseLiteral("srcip2", R"(........)", false, false),
    };

    auto merged = combinator::merge(list);

    // Input
    auto strEv = ev1 + ev2 + ev3;

    InputP input = InputP(strEv.c_str());
    json::Json jsonRes {};

    for (auto _ : state)
    {
        auto result = merged(input);
        if (result) {
            auto listFn = result.popValue().value();
            for (auto& fn : listFn)
            {
                fn(jsonRes);
            }
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);

    }


}BENCHMARK(merged_combinators_error_lit_4)->Range(4, 4 << 4);
