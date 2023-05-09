#include <string>
#include <iostream>

#include <arpa/inet.h>

#include <benchmark/benchmark.h>

#include <hlp/hlp.hpp>
#include <hlp/logpar.hpp>
#include <json/json.hpp>

// Namespace anonimo para parsers benchmarks
// **********************************************************************************************************************
namespace {

using jFnList = hlp::logpar::fnList<json::Json>;

// parseQuotedString
// Parser para cadenas de texto entre comillas dobles
parsec::MergeableParser<jFnList>
getParseQuotedString(std::string name, std::string path, std::list<std::string> endTokens, std::vector<std::string> lst)
{

    path = json::Json::formatJsonPath(path);
    auto enableCapure = true;

    // Semantic action
    auto m_semanticProcessor = [path](jFnList& result,
                                      const std::deque<std::string_view>& tokens,
                                      const parsec::ParserState& state) -> std::pair<bool, std::optional<parsec::TraceP>>
    {
        if (tokens.size() == 0)
        {
            return {true, std::nullopt};
        }

        result.push_back([path, value = std::string(tokens.front())](json::Json& json) { json.setString(value, path); });
        return {true, std::nullopt};
    };

    // Sintactic action
    return [m_semanticProcessor, enableCapure](const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
    {
        auto result = parsec::MergeableResultP<jFnList>::failure(state);

        if (state.getRemainingSize() == 0)
        {
            if (state.isTraceEnabled())
            {
                return result.concatenateTraces("Unexpected EOF, expected '\"'");
            }
            return result;
        }

        auto inputStr = state.getRemainingData();
        if (inputStr.front() != '"')
        {
            if (state.isTraceEnabled())
            {
                result.concatenateTraces("Expected '\"' but found '" + std::string(1, inputStr.front()) + "'");
            }
            return result;
        }

        bool isValidQuote = false;
        std::size_t offset = 1;
        // Search for the end the next '"' that is not escaped
        while (offset < inputStr.size())
        {
            if (inputStr[offset] == '"' && inputStr[offset - 1] != '\\')
            {
                isValidQuote = true;
                break;
            }
            offset++;
        }

        if (!isValidQuote)
        {
            if (state.isTraceEnabled())
            {
                result.concatenateTraces("Unexpected EOF, expected '\"'");
            }
            return result;
        }


        if (enableCapure)
        {
            result.setSuccess(state.advance(offset + 1),
                              {m_semanticProcessor, jFnList(), {inputStr.substr(1, offset - 1)}});
        } else
        {
            result.setSuccess(state.advance(offset + 1),
                              {m_semanticProcessor, jFnList(), {}});
        }

        if (state.isTraceEnabled())
        {
            result.concatenateTraces("Found quoted string: " + std::string(inputStr.substr(1, offset - 1)));
        }

        return result;
    };
}

// Parse a IP
parsec::MergeableParser<jFnList>
getParserIP(std::string name, std::string path, std::list<std::string> endTokens, std::vector<std::string> lst) {

        path = json::Json::formatJsonPath(path);
        bool enableCapure = true;

        if (endTokens.empty())
        {
            throw std::runtime_error("IP parser needs a stop string");
        }

        if (lst.size() > 0)
        {
            throw std::runtime_error("The IP parser does not accept any argument");
        }

        // Semantic action
        auto m_semanticProcessor =
            [path, enableCapure](jFnList& result,
                                 const std::deque<std::string_view>& tokens,
                                 const parsec::ParserState& state) -> std::pair<bool, std::optional<parsec::TraceP>>
        {
            // tokens.size() == 1
            auto srcip = std::string(tokens.front());

            // Check if the IP is valid
            struct in_addr ipv4;
            struct in6_addr ipv6;
            if (inet_pton(AF_INET, srcip.c_str(), &ipv4) || inet_pton(AF_INET6, srcip.c_str(), &ipv6))
            {
                if (enableCapure)
                {
                    result.push_back([path, value = std::move(srcip)](json::Json& json) { json.setString(value, path); });
                }
                return {true, std::nullopt};
            }

            if (state.isTraceEnabled())
            {
                auto trace = fmt::format("Invalid IP address: {}", srcip);
                auto offset = srcip.data() - state.getData().data();
                return {false, parsec::TraceP(trace, offset)};
            }

            return {false, std::nullopt};
        };

        // Sintactic action
        return [m_semanticProcessor, endToken = endTokens.front()] (const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
        {
            auto result = parsec::MergeableResultP<jFnList>::failure(state);
            if (state.getRemainingSize() == 0)
            {
                if (state.isTraceEnabled())
                {
                    result.concatenateTraces("Unexpected EOF, expected IP address");
                }
                return result;
            }

            auto inputStr = state.getRemainingData();

            auto until = endToken.size() ? inputStr.find(endToken) : inputStr.length();
            if (until == std::string_view::npos)
            {
                if (state.isTraceEnabled())
                {
                    result.concatenateTraces(fmt::format("Unexpected EOF, expected '{}'", endToken));
                }
                return result;
            }

            auto IpCandidate = inputStr.substr(0, until);
            // Check long IP
            constexpr std::size_t IPv6Length = std::char_traits<char>::length("fd7a:115c:a1e0:ab12:4843:cd96:626d:1730");
            if (IpCandidate.size() > IPv6Length)
            {
                if (state.isTraceEnabled())
                {
                    auto msg = "Invalid IP address: '" + std::string(IpCandidate) + "', is too long";
                    result.concatenateTraces(parsec::TraceP(msg, state.getOffset()));
                }
                return result;
            }

            // Add the IP to the result
            return parsec::MergeableResultP<jFnList>::success(state.advance(until),
                                                             {m_semanticProcessor, jFnList(), {IpCandidate}});

        };

}

// Parse a Number
parsec::MergeableParser<jFnList>
getParseNumber(std::string name, std::string path, std::list<std::string> endTokens, std::vector<std::string> lst) {

        path = json::Json::formatJsonPath(path);
        bool enableCapure = true;

        // Semantic action
        auto m_semanticProcessor =
            [path, enableCapure](jFnList& result, const std::deque<std::string_view>& tokens, const parsec::ParserState& state)
                -> std::pair<bool, std::optional<parsec::TraceP>>
        {
            // tokens.size() == 1
            auto number = std::string(tokens.front());

            // Convert to int
            try
            {
                auto value = std::stoi(number);
                if (enableCapure)
                {
                    result.push_back([path, value](json::Json& json) { json.setInt(value, path); });
                }
                return {true, std::nullopt};
            }
            catch (const std::invalid_argument& e)
            {
                if (state.isTraceEnabled())
                {
                    auto offset = tokens.front().data() - state.getData().data();
                    return {false, parsec::TraceP("Invalid number: '" + number + "' is not a number", offset)};
                }
                return {false, std::nullopt};
            }
            catch (const std::out_of_range& e)
            {
                if (state.isTraceEnabled())
                {
                    auto offset = tokens.front().data() - state.getData().data();
                    return {false, parsec::TraceP("Invalid number: '" + number + "' is out of range", offset)};
                }
                return {false, std::nullopt};
            }

            return {false, std::nullopt};

        };

        // Sintactic action
        return [m_semanticProcessor](const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
        {
            auto result = parsec::MergeableResultP<jFnList>::failure(state);

            if (state.getRemainingSize() == 0)
            {
                if (state.isTraceEnabled())
                {
                    result.concatenateTraces("Unexpected EOF, expected number");
                }
                return result;
            }

            auto inputStr = state.getRemainingData();
            // Check if the number is valid
            auto until = inputStr.find_first_not_of("0123456789", inputStr[0] == '-' ? 1 : 0);
            if (until == std::string_view::npos)
            {
                until = inputStr.length();
            }
            else if (until == 0)
            {
                if (state.isTraceEnabled())
                {
                    auto trace = fmt::format("Unexpected character '{}', expected number",
                                             std::string(1, inputStr[0] == '-' ? inputStr[1] : inputStr[0]));
                    result.concatenateTraces(trace);
                }
                return result;
            }
            auto numberCandidate = inputStr.substr(0, until);

            // Add the number to the result
            return parsec::MergeableResultP<jFnList>::success(state.advance(until),
                                                             {m_semanticProcessor, jFnList(), {numberCandidate}});
        };
}

// Parse any string
parsec::MergeableParser<jFnList>
getParserAny(std::string name, std::string path, std::list<std::string> endTokens, std::vector<std::string> lst)
{
    path = json::Json::formatJsonPath(path);
    bool enableCapure = true;

    if (endTokens.empty())
    {
        throw std::runtime_error("Invalid end tokens, cannot be empty");
    }

    // Semantic action
    auto m_semanticProcessor =
        [path, enableCapure](jFnList& result, const std::deque<std::string_view>& tokens, const parsec::ParserState& state)
            -> std::pair<bool, std::optional<parsec::TraceP>>
    {
        if (enableCapure)
        {
            auto value = std::string(tokens.front());
            result.push_back([path, value](json::Json& json) { json.setString(value, path); });
        }
        return {true, std::nullopt};
    };

    // Sintactic action
    return [m_semanticProcessor, endToken = endTokens.front()](const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
    {

        auto result = parsec::MergeableResultP<jFnList>::failure(state);

        if (state.getRemainingSize() == 0)
        {
            if (state.isTraceEnabled())
            {
               result.concatenateTraces("Unexpected EOF, expected string");
            }
            return result;
        }

        auto inputStr = state.getRemainingData();

        auto until = endToken.size() ? inputStr.find(endToken) : inputStr.length();
        if (until == std::string_view::npos)
        {
            if (state.isTraceEnabled())
            {
                result.concatenateTraces("Expected end '" + endToken + "' but not found");
            }
            return result;
        }
        auto valueCandidate = inputStr.substr(0, until);

        // Add the value to the result
        return result.setSuccess(state.advance(until), {m_semanticProcessor, jFnList(), {valueCandidate}});
    };
}


// Parse literal
parsec::MergeableParser<jFnList>
getParseLiteral(std::string name, std::string path, std::list<std::string>, std::vector<std::string> lst)
{
    if (lst.size() != 1)
    {
        throw(std::runtime_error("Literal parser requires exactly one option"));
    }


    // Semantic action
    auto m_semanticProcessor = [](jFnList&,
                                      const std::deque<std::string_view>&,
                                      const parsec::ParserState&) -> std::pair<bool, std::optional<parsec::TraceP>>
    {
        return {true, std::nullopt};
    };

    // Sintactic action
    return [m_semanticProcessor, literal = lst[0]](const parsec::ParserState& state) -> parsec::MergeableResultP<jFnList>
    {
        auto result = parsec::MergeableResultP<jFnList>::failure(state);
       if (state.getRemainingSize() == 0)
        {
            if (state.isTraceEnabled())
            {
                result.concatenateTraces("Unexpected EOF, expected literal '" + literal + "'");
            }
            return result;
        }

        auto inputStr = state.getRemainingData();

        // Compare the literal
        if (inputStr.substr(0, literal.size()) != literal)
        {
            if (state.isTraceEnabled())
            {
                result.concatenateTraces("Expected literal '" + literal + "' but found '" + std::string(inputStr) + "'");
            }
            return result;
        }

        return result.setSuccess(state.advance(literal.size()), {m_semanticProcessor, jFnList(), {}});

    };
}
}

// **********************************************************************************************************************

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

    ret.registerBuilder(hlp::ParserType::P_LONG, getParseNumber);
    ret.registerBuilder(hlp::ParserType::P_TEXT, getParserAny);
    ret.registerBuilder(hlp::ParserType::P_QUOTED, getParseQuotedString);
    ret.registerBuilder(hlp::ParserType::P_IP, getParserIP);
    ret.registerBuilder(hlp::ParserType::P_LITERAL, getParseLiteral);

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
    //std::string ev1 = "hola";
    parserStr += ev1;

    // IP:Number
    std::string ev2 = "127.0.0.1:8080";
    parserStr += "<~srcip/ip>:<~port/long>";

    // Quoted string
    std::string ev3 = "\"" + getRandomString(state.range(0)) + "\"";
    parserStr += "<~quoted/quoted>";

    auto parser = logpar.build(parserStr);
    auto ev = ev1 + ev2 + ev3;


    auto input = parsec::ParserState(ev, false);
    for (auto _ : state)
    {
        auto result = parser(input);
        if (result.isFailure())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

    /*
    auto result = parser(input);
    auto listCallback = result.popValue();
    json::Json jres {};
    for (auto& cb : listCallback)
    {
        cb(jres);
    }
    std::cout << jres.prettyStr() << std::endl;
    */
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

    auto input = parsec::ParserState(ev, false);

    for (auto _ : state)
    {
        auto result = parser(input);
        if (result.isSuccessful())
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
    auto input = parsec::ParserState(ev, false);

    for (auto _ : state)
    {
        auto result = parser(input);
        if (result.isSuccessful())
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
    auto input = parsec::ParserState(ev, false);

    for (auto _ : state)
    {
        auto result = parser(input);
        if (result.isSuccessful())
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
    auto input = parsec::ParserState(ev, false);


    for (auto _ : state)
    {
        auto result = parser(input);
        if (result.isSuccessful())
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
    auto input = parsec::ParserState(ev, false);

    for (auto _ : state)
    {
        auto result = parser(input);
        if (result.isSuccessful())
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
    auto input = parsec::ParserState(ev, false);

    for (auto _ : state)
    {
        auto result = parser(input);
        if (result.isSuccessful())
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
    auto input = parsec::ParserState(ev, false);

    for (auto _ : state)
    {
        auto result = parser(input);
        if (result.isSuccessful())
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
    auto input = parsec::ParserState(ev, false);

    for (auto _ : state)
    {
        auto result = parser(input);
        if (result.isSuccessful())
        {
            state.SkipWithError("Parsing failed");
        }
        benchmark::DoNotOptimize(result);
    }

}
BENCHMARK(logpar_parse_error_LIT_4)->Range(4, 4 << 4);
