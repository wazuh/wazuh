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

static std::string createRandomFilepath(int len, bool unixFormat = false, int length = 5)
{
    std::string ret, folder_separator;
    if(unixFormat){
        folder_separator = '/';
        ret += getRandomString(len);
    }
    else {
        folder_separator = '\\';
        ret += "C:\\";
    }
    for(int i = 0; i < length; i++){
        ret += getRandomString(len) + folder_separator ;
    }

    return ret;
}

static std::string createRandomDomain(int len, bool withSubdomain = false)
{
    std::string ret;
    ret += "www.";
    if(withSubdomain){
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

// TODO Probably need a way to mix-match a variable number of all our parsers
static const char *logQL_expression = "<source.address> - <JSON> - [<timestamp/APACHE>] \"<http.request.method> "
    "<url> HTTP/<http.version>\" <http.response.status_code> <http.response.body.bytes> \"-\" "
    "\"<user_agent.original>\"";
static const char *event = "monitoring-server - {\"data\":\"this is a json\"} - [29/May/2017:19:02:48 +0000] "
    "\"GET https://user:password@wazuh.com:8080/status?query=%22a%20query%20with%20a%20space%22#fragment "
    "HTTP/1.1\" 200 612 \"-\" \"Mozilla/5.0 (Windows NT 6.1; rv:15.0) Gecko/20120716 Firefox/15.0a2\"";

static void capture_expr_parse(benchmark::State &state)
{
    auto expr = getRandomCapExpr(state.range(0));
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

static void execute_parsers(benchmark::State &state)
{
    auto parseOp = getParserOp(logQL_expression);
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
        auto parseOp = getParserOp(logQL_expression);
        auto result = parseOp(event);
    }
}
BENCHMARK(full_pass);

// Url parsing
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

// IP parsing
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

// JSON parsing
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

// Map parsing
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

// Timestamp parsing
static void timestamp_specific_format_parse(benchmark::State &state)
{
    for (auto _ : state) {
        TimeStampResult tsr;
        std::vector<std::string> const opts = {"RubyDate"};
        // TODO: does it add any value if I create a random date generator?
        const char *it = "Mon Jan 02 15:04:05 -0700 2006";
        if(!parseTimeStamp(&it, opts, 0, tsr)) {
            state.SkipWithError("Parser Failed");
        }
    }
}
BENCHMARK(timestamp_specific_format_parse);

static void timestamp_without_format_parse(benchmark::State &state)
{
    for (auto _ : state) {
        TimeStampResult tsr;
        std::vector<std::string> const opts = {};
        const char *it = "Mon Jan 2 15:04:05 MST 2006";
        if(!parseTimeStamp(&it, opts, 0, tsr)) {
            state.SkipWithError("Parser Failed");
        }
    }
}
BENCHMARK(timestamp_without_format_parse);

// Domain parsing
static void domain_parse(benchmark::State &state)
{
    std::string ev = createRandomDomain(state.range(0));
    std::vector<std::string> const opts = { };
    DomainResult domainResult;

    for (auto _ : state) {
        const char *eventIt = ev.c_str();
        if (!parseDomain(&eventIt, 0, opts,domainResult)) {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(domain_parse)->Range(3, 63);

static void domain_withSubdomain_parse(benchmark::State &state)
{
    std::string ev = createRandomDomain(state.range(0),true);
    std::vector<std::string> const opts = { };
    DomainResult domainResult;

    for (auto _ : state) {
        const char *eventIt = ev.c_str();
        if (!parseDomain(&eventIt, 0, opts,domainResult)) {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(domain_withSubdomain_parse)->Range(3, 63);

// Filepath parsing
static void filepath_parse(benchmark::State &state)
{
    std::string ev = createRandomFilepath(state.range(0));
    std::vector<std::string> const opts = { };
    FilePathResult filePathResult;

    for (auto _ : state) {
        const char *eventIt = ev.c_str();
        parseFilePath(&eventIt, 0, opts,filePathResult);
        if (filePathResult.path.empty()) {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(filepath_parse)->Range(8, 8 << 8);

static void filepath_variable_length_parse(benchmark::State &state)
{
    std::string ev = createRandomFilepath(state.range(0),false, state.range(0));
    std::vector<std::string> const opts = { };
    FilePathResult filePathResult;

    for (auto _ : state) {
        const char *eventIt = ev.c_str();
        parseFilePath(&eventIt, 0, opts,filePathResult);
        if (filePathResult.path.empty()) {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(filepath_variable_length_parse)->Range(8, 8 << 8);

static void unix_filepath_parse(benchmark::State &state)
{
    std::string ev = createRandomFilepath(state.range(0),true);
    std::vector<std::string> const opts = { };
    FilePathResult filePathResult;

    for (auto _ : state) {
        const char *eventIt = ev.c_str();
        parseFilePath(&eventIt, 0, opts,filePathResult);
        if (filePathResult.path.empty()) {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(unix_filepath_parse)->Range(8, 8 << 8);

static void unix_filepath_variable_length_parse(benchmark::State &state)
{
    std::string ev = createRandomFilepath(state.range(0),true, state.range(0));
    std::vector<std::string> const opts = { };
    FilePathResult filePathResult;

    for (auto _ : state) {
        const char *eventIt = ev.c_str();
        parseFilePath(&eventIt, 0, opts,filePathResult);
        if (filePathResult.path.empty()) {
            state.SkipWithError("Parser failed");
        }
    }
}
BENCHMARK(unix_filepath_variable_length_parse)->Range(8, 8 << 8);
