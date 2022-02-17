#include <string>

#include <benchmark/benchmark.h>

// Including this private header directly to be able to
// benchmark individual parsers.
// Regular users of the library should NOT do this
#include "src/SpecificParsers.hpp"
#include <hlp/hlp.hpp>


static std::string getRandomString(int len, bool includeSymbols = false) {
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    static const char symbols[] =
        "-_'\\/. *!\"#$%&()+[]{},;";

    std::string tmp_s;
    tmp_s.reserve(len);

    std::string dict = alphanum;
    if(includeSymbols)
    {
        dict += symbols;
    }

    for (int i = 0; i < len; ++i) {
        tmp_s += dict[rand() % dict.size()];
    }
    return tmp_s;
}

static std::string getRandomCapExprVariable(int len){
    std::string ret;
    for(int i = 0; i < len; ++i){
        ret += '<';
        ret += getRandomString((rand() % 10) + 1);
        for(int j = 0; j < (rand() % 5); ++j){
            ret += '/';
            ret += getRandomString((rand() % 10) + 1);
        }
        ret += '>';
        ret += getRandomString((rand() % 50) + 1, true);
    }

    return ret;
}

static std::string getRandomCapExpr(int len){
    std::string ret;
    for(int i = 0; i < len; ++i){
        ret += '<';
        ret += getRandomString(10);
        for(int j = 0; j < 4; ++j){
            ret += '/';
            ret += getRandomString(10);
        }
        ret += '>';
        ret += getRandomString(15, true);
    }

    return ret;
}
// TODO Probably need a way to mix-match a variable number of all our parsers
static const char *logQl =
    "<source.address> - <JSON> - [<timestamp/APACHE>] \"<http.request.method> "
    "<url> HTTP/<http.version>\" <http.response.status_code> "
    "<http.response.body.bytes> \"-\" \"<user_agent.original>\"";
static const char *event =
    "monitoring-server - {\"data\":\"this is a json\"} - [29/May/2017:19:02:48 +0000] "
    "\"GET "
    "https://user:password@wazuh.com:8080/"
    "status?query=%22a%20query%20with%20a%20space%22#fragment HTTP/1.1\" 200 612 \"-\" "
    "\"Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20120716 Firefox/15.0a2\"";

static void capture_expr_parse(benchmark::State &state)
{
    auto expr = getRandomCapExpr(state.range(0));
    printf("%s\n", expr.c_str());
    for (auto _ : state)
    {
        auto parseOp = getParserOp(expr);
        if(!parseOp){
            state.SkipWithError("Invalid expr");
        }
    }
}
BENCHMARK(capture_expr_parse)->Range(8, 8 << 10);

static void capture_var_expr_parse(benchmark::State &state)
{
    auto expr = getRandomCapExprVariable(state.range(0));
    for (auto _ : state)
    {
        auto parseOp = getParserOp(expr);
        if(!parseOp){
            state.SkipWithError("Invalid expr");
        }
    }
}
BENCHMARK(capture_var_expr_parse)->Range(8, 8 << 10);

static void execute_parsers(benchmark::State &state)
{
    auto parseOp = getParserOp(logQl);
    for (auto _ : state)
    {
        auto result = parseOp(event);
    }
}
BENCHMARK(execute_parsers);

static void full_pass(benchmark::State &state)
{
    for (auto _ : state)
    {
        auto parseOp = getParserOp(logQl);
        auto result = parseOp(event);
    }
}
BENCHMARK(full_pass);

static void url_parse(benchmark::State &state)
{
    const char *ev = "https://user:password@wazuh.com:8080/"
                      "status?query=%22a%20query%20with%20a%20space%22#fragment";

    for (auto _ : state)
    {
        const char *eventIt = ev;
        URLResult res;
        parseURL(&eventIt, 0, res);
    }
}
BENCHMARK(url_parse);

static void ipv4_parse(benchmark::State &state)
{
    const char *ev = "127.0.0.1";

    for (auto _ : state)
    {
        const char *eventIt = ev;
        parseIPaddress(&eventIt, 0);
    }
}
BENCHMARK(ipv4_parse);

static void ipv6_parse(benchmark::State &state)
{
    const char *ev = "2001:db8:3333:4444:CCCC:DDDD:EEEE:FFFF";

    for (auto _ : state)
    {
        const char *eventIt = ev;
        parseIPaddress(&eventIt, 0);
    }
}
BENCHMARK(ipv6_parse);

static void match_literal_range(benchmark::State &state)
{
    srand((unsigned)time(NULL));
    std::string ev = getRandomString(state.range(0));
    for (auto _ : state)
    {
        const char *eventIt = ev.c_str();
        if(!matchLiteral(&eventIt, ev)){
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(match_literal_range)->Range(8, 8 << 11);

static void json_parse(benchmark::State &state)
{
    std::string ev =
        "{\"id\": \"It has been suggested that he adopted Christianity as part of a settlement "
        "with Oswiu.\",\"name\": \"Its upperparts and sides are grey, but elongated grey feathers "
        "with black central stripes are draped across the back from the shoulder "
        "area.\",\"email\": \"rita_sakellariou@vancouver.edu\",\"bio\": \"Wintjiya came from an "
        "area north-west or north-east of Walungurru (the Pintupi-language name for Kintore, "
        "Northern Territory).\",\"age\": 39,\"avatar\": \"However, she refused to admit her guilt "
        "to the end, and had given no evidence against any others of the accused.\"}";

    ev += getRandomCapExpr(20);
    for (auto _ : state) {
        const char *eventIt = ev.c_str();
        if (parseJson(&eventIt).empty()) {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(json_parse);

static std::string createMap(int len)
{
    std::string ret;
    for(int i = 0; i < len; ++i){
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

static void map_parse(benchmark::State &state)
{
    std::string ev = createMap(state.range(0));
    std::vector<std::string> opts {" ", "=", ";"};

    ev += getRandomString(20);
    for (auto _ : state) {
        const char *eventIt = ev.c_str();
        if (parseMap(&eventIt, 0, opts).empty()) {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(map_parse)->Range(8, 8 << 10);
