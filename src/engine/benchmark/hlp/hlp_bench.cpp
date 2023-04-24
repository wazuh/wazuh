#include <string>

#include <benchmark/benchmark.h>

#include "src/hlpDetails.hpp"
#include "src/specificParsers.hpp"
#include <hlp/hlp.hpp>

using namespace hlp;

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

static std::string getRandomCapExprVariable(int len)
{
    std::string ret;
    for (int i = 0; i < len; ++i)
    {
        ret += '<';
        ret += '~';
        ret += getRandomString((rand() % 10) + 1);
        for (int j = 0; j < (rand() % 5); ++j)
        {
            ret += '/';
            ret += getRandomString((rand() % 10) + 1);
        }
        ret += '>';
        ret += getRandomString((rand() % 50) + 1, true);
    }

    return ret;
}

static std::string getRandomCapExpr(int len)
{
    std::string ret;
    for (int i = 0; i < len; ++i)
    {
        ret += '<';
        ret += '~';
        ret += getRandomString(10);
        for (int j = 0; j < 4; ++j)
        {
            ret += '/';
            ret += getRandomString(10);
        }
        ret += '>';
        ret += getRandomString(15, true);
    }

    return ret;
}

static std::string createRandomFilepath(int folder_name_length,
                                        bool unixFormat = false,
                                        int folders_qtty = 5)
{
    std::string ret, folder_separator;
    if (unixFormat)
    {
        folder_separator = '/';
    }
    else
    {
        folder_separator = '\\';
        ret += "C:\\";
    }
    for (int i = 0; i < folders_qtty; i++)
    {
        ret += getRandomString(folder_name_length) + folder_separator;
    }

    return ret;
}

static std::string createRandomDomain(int len, bool withSubdomain = false)
{
    std::string ret;
    ret += "www.";
    if (withSubdomain)
    {
        ret += getRandomString(len) + '.';
    }
    ret += getRandomString(len);
    ret += ".com/";
    ret += getRandomString(len);

    return ret;
}

static std::string createMap(int len)
{
    std::string ret;
    for (int i = 0; i < len; ++i)
    {
        ret += "key";
        ret += std::to_string(i);
        ret += '=';
        ret += getRandomString(10);
        if (i != (len - 1))
            ret += ' ';
    }
    ret += ';';

    return ret;
}

static void getting_parser_from_expression(benchmark::State& state)
{
    auto expr = getRandomCapExpr(state.range(0));
    for (auto _ : state)
    {
        auto parseOp = getParserOp(expr);
        if (!parseOp)
        {
            state.SkipWithError("Invalid expr");
        }
    }
}
BENCHMARK(getting_parser_from_expression)->Range(8, 8 << 10);

static void getting_parser_from_variable_length_expression(benchmark::State& state)
{
    auto expr = getRandomCapExprVariable(state.range(0));
    for (auto _ : state)
    {
        auto parseOp = getParserOp(expr);
        if (!parseOp)
        {
            state.SkipWithError("Invalid expr");
        }
    }
}
BENCHMARK(getting_parser_from_variable_length_expression)->Range(8, 8 << 10);

static void match_literal_range(benchmark::State& state)
{
    srand((unsigned)time(NULL));
    std::string ev = getRandomString(state.range(0));
    Parser p;
    p.name = ev;
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!matchLiteral(&eventIt, p, result))
        {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(match_literal_range)->Range(8, 8 << 11);
/*
static void getting_result_from_defined_parser(benchmark::State& state)
{
    // TODO Probably need a way to mix-match a variable number of all our
    // parsers
    const char* logparExpression =
        "<source.address> - <JSON> - [<timestamp/APACHE>]"
        " \"<http.request.method> <url> HTTP/<http.version>\" "
        "<http.response.status_code> <http.response.body.bytes> \"-\" "
        "\"<user_agent.original>\"";
    const char* event =
        "monitoring-server - {\"data\":\"this is a json\"} - "
        "[29/May/2017:19:02:48 +0000] \"GET https://user:password@wazuh.com"
        ":8080/status?query=%22a%20query%20with%20a%20space%22#fragment "
        "HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0 (Windows NT 6.1; rv:15.0)"
        " Gecko/20120716 Firefox/15.0a2\"";

    auto parseOp = getParserOp(logparExpression);
    for (auto _ : state)
    {
        ParseResult result;
        bool ret = parseOp(event, result);
    }
}
BENCHMARK(getting_result_from_defined_parser);

static void getting_result_from_defined_expression(benchmark::State& state)
{
    const char* logparExpression =
        "<source.address> - <JSON> - [<timestamp/APACHE>]"
        " \"<http.request.method> <url> HTTP/<http.version>\" "
        "<http.response.status_code> <http.response.body.bytes> \"-\" "
        "\"<user_agent.original>\"";
    const char* event =
        "monitoring-server - {\"data\":\"this is a json\"} - "
        "[29/May/2017:19:02:48 +0000] \"GET https://user:password@wazuh.com"
        ":8080/status?query=%22a%20query%20with%20a%20space%22#fragment "
        "HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0 (Windows NT 6.1; rv:15.0)"
        " Gecko/20120716 Firefox/15.0a2\"";

    for (auto _ : state)
    {
        auto parseOp = getParserOp(logparExpression);
        ParseResult result;
        bool ret = parseOp(event, result);
    }
}
BENCHMARK(getting_result_from_defined_expression);
*/
// Url parsing
static void url_parse(benchmark::State& state)
{
    const char* ev = "https://user:password@wazuh.com:8080/"
                     "status?query=%22a%20query%20with%20a%20space%22#fragment";

    Parser p;
    p.name = "URL";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev;
        parseURL(&eventIt, p, result);
    }
}
BENCHMARK(url_parse);

// IP parsing
static void ipv4_parse(benchmark::State& state)
{
    const char* ev = "127.0.0.1";

    Parser p;
    p.name = "IP";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev;
        if (!parseIPaddress(&eventIt, p, result))
        {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(ipv4_parse);

static void ipv6_parse(benchmark::State& state)
{
    const char* ev = "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF";

    Parser p;
    p.name = "IP";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev;
        if (!parseIPaddress(&eventIt, p, result))
        {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(ipv6_parse);

// JSON parsing
static void json_parse(benchmark::State& state)
{
    std::string ev =
        "{\"id\": \"It has been suggested that he adopted Christianity as part "
        "of a settlement "
        "with Oswiu.\",\"name\": \"Its upperparts and sides are grey, but "
        "elongated grey feathers "
        "with black central stripes are draped across the back from the "
        "shoulder "
        "area.\",\"email\": \"rita_sakellariou@vancouver.edu\",\"bio\": "
        "\"Wintjiya came from an "
        "area north-west or north-east of Walungurru (the Pintupi-language "
        "name for Kintore, "
        "Northern Territory).\",\"age\": 39,\"avatar\": \"However, she refused "
        "to admit her guilt "
        "to the end, and had given no evidence against any others of the "
        "accused.\"}";

    Parser p;
    p.name = "JSON";
    p.endToken = '\0';
    ParseResult result;
    ev += getRandomCapExpr(20);
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseJson(&eventIt, p, result))
        {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(json_parse);

// Map parsing
static void map_parse(benchmark::State& state)
{
    std::string ev = createMap(state.range(0));
    std::vector<std::string> opts {" ", "=", ";"};

    Parser p;
    p.name = "map";
    p.endToken = '\0';
    p.options.push_back(" =;");
    ParseResult result;
    ev += getRandomString(20);
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseKVMap(&eventIt, p, result))
        {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(map_parse)->Range(8, 8 << 10);

// Timestamp parsing
static void timestamp_specific_format_parse(benchmark::State& state)
{
    Parser p;
    p.name = "ts";
    p.endToken = '\0';
    p.options.push_back("%a %b %d %H:%M:%S %z %Y");
    ParseResult result;
    for (auto _ : state)
    {
        const char* it = "Mon Jan 02 15:04:05 -0700 2006";
        if (!parseTimeStamp(&it, p, result))
        {
            state.SkipWithError("Parser Failed");
        }
    }
}
BENCHMARK(timestamp_specific_format_parse);

static void timestamp_without_format_parse(benchmark::State& state)
{
    Parser p;
    p.name = "ts";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* it = "Mon Jan 2 15:04:05 MST 2006";
        if (!parseTimeStamp(&it, p, result))
        {
            state.SkipWithError("Parser Failed");
        }
    }
}
BENCHMARK(timestamp_without_format_parse);

// Domain parsing
static void domain_parse(benchmark::State& state)
{
    std::string ev = createRandomDomain(state.range(0));
    Parser p;
    p.name = "domain";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseDomain(&eventIt, p, result))
        {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(domain_parse)->Range(3, 63);

static void domain_withSubdomain_parse(benchmark::State& state)
{
    std::string ev = createRandomDomain(state.range(0), true);

    Parser p;
    p.name = "domain";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseDomain(&eventIt, p, result))
        {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(domain_withSubdomain_parse)->Range(3, 63);

// Filepath parsing
static void filepath_parse(benchmark::State& state)
{
    std::string ev = createRandomFilepath(state.range(0));

    Parser p;
    p.name = "filepath";
    p.endToken = '\0';
    p.options.push_back("/\\");
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseFilePath(&eventIt, p, result))
            state.SkipWithError("Parser failed");
    }
}
BENCHMARK(filepath_parse)->Range(8, 8 << 8);

static void filepath_variable_length_parse(benchmark::State& state)
{
    std::string ev = createRandomFilepath(state.range(0), false, state.range(0));

    Parser p;
    p.name = "filepath";
    p.endToken = '\0';
    p.options.push_back("/\\");
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseFilePath(&eventIt, p, result))
            state.SkipWithError("Parser failed");
    }
}
BENCHMARK(filepath_variable_length_parse)->Range(8, 8 << 8);

static void unix_filepath_parse(benchmark::State& state)
{
    std::string ev = createRandomFilepath(state.range(0), true);

    Parser p;
    p.name = "filepath";
    p.endToken = '\0';
    p.options.push_back("/\\");
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseFilePath(&eventIt, p, result))
            state.SkipWithError("Parser failed");
    }
}
BENCHMARK(unix_filepath_parse)->Range(8, 8 << 8);

static void unix_filepath_variable_length_parse(benchmark::State& state)
{
    std::string ev = createRandomFilepath(state.range(0), true, state.range(0));

    Parser p;
    p.name = "filepath";
    p.endToken = '\0';
    p.options.push_back("/\\");
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseFilePath(&eventIt, p, result))
            state.SkipWithError("Parser failed");
    }
}
BENCHMARK(unix_filepath_variable_length_parse)->Range(8, 8 << 8);

static void any_string_variable_length_parse(benchmark::State& state)
{
    std::string ev = getRandomString(state.range(0));

    Parser p;
    p.name = "any";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseAny(&eventIt, p, result))
            state.SkipWithError("Parser failed");
    }
}
BENCHMARK(any_string_variable_length_parse)->Range(8, 8 << 8);

static void keyword_variable_length_parse(benchmark::State& state)
{
    std::string ev = getRandomString(state.range(0));

    Parser p;
    p.name = "keyword";
    p.endToken = ' ';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str() + ' ';
        if (!parseAny(&eventIt, p, result))
            state.SkipWithError("Parser failed");
    }
}
BENCHMARK(keyword_variable_length_parse)->Range(8, 8 << 8);

static void integer_number_variable_length_parse(benchmark::State& state)
{
    std::string ev = getRandomString(state.range(0), false, true);

    Parser p;
    p.name = "file.size";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseNumber(&eventIt, p, result))
            state.SkipWithError("Parser failed");
    }
}
BENCHMARK(integer_number_variable_length_parse)->Range(8, 18);

static void float_number_variable_length_parse(benchmark::State& state)
{
    std::string ev = getRandomString(state.range(0), false, true, true);

    Parser p;
    p.name = "file.size";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseNumber(&eventIt, p, result))
            state.SkipWithError("Parser failed");
    }
}
BENCHMARK(float_number_variable_length_parse)->Range(8, 31);

static void quoted_string_variable_length_parse(benchmark::State& state)
{
    std::string ev = "\"" + getRandomString(state.range(0)) + "\"";

    Parser p;
    p.options.push_back("\"");
    p.options.push_back("\"");
    p.name = "quoted_string";
    p.endToken = '\0';
    ParseResult result;
    for (auto _ : state)
    {
        const char* eventIt = ev.c_str();
        if (!parseQuotedString(&eventIt, p, result))
            state.SkipWithError("Parser failed");
    }
}
BENCHMARK(quoted_string_variable_length_parse)->Range(8, 8 << 8);


static void getting_result_from_defined_expression(benchmark::State& state)
{
    const char* logparExpression =
        "<source.address> - <JSON> - [<timestamp/APACHE>]"
        " \"<http.request.method> <url> HTTP/<http.version>\" "
        "<http.response.status_code> <http.response.body.bytes> \"-\" "
        "\"<user_agent.original>\"";
    const char* event =
        "monitoring-server - {\"data\":\"this is a json\"} - "
        "[29/May/2017:19:02:48 +0000] \"GET https://user:password@wazuh.com"
        ":8080/status?query=%22a%20query%20with%20a%20space%22#fragment "
        "HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0 (Windows NT 6.1; rv:15.0)"
        " Gecko/20120716 Firefox/15.0a2\"";

    for (auto _ : state)
    {
        auto parseOp = getParserOp(logparExpression);
        ParseResult result;
        bool ret = parseOp(event, result);
    }
}
BENCHMARK(getting_result_from_defined_expression);
*/
