#ifndef _TEST_UTILS_H
#define _TEST_UTILS_H

#include <algorithm>
#include <iostream>
#include <map>
#include <rxcpp/rx.hpp>
#include <string>
#include <vector>

#include "json.hpp"

#define GTEST_COUT std::cout << "[          ] [ INFO ] "

using event_t = json::Document;
using value_t = const json::Value *;
using namespace std;
using namespace rxcpp;

event_t generate(std::string name, std::string source)
{
    auto t = std::time(nullptr);
    auto tm = *std::gmtime(&t);

    std::string cstr(30, '\0');
    auto len = std::strftime(&cstr[0], cstr.size(), "%FT%TZ%z", &tm);
    cstr.erase(len, std::string::npos);
    auto j_string = "{\"module\": { \"name\": \"" + name + "\", \"source\": \"" + source + "\"}}";
    return event_t{j_string.c_str()};
}

auto handler = [](subscriber<event_t> s)
{
    s.on_next(generate("logcollector", "apache-access"));
    s.on_next(generate("logcollector", "apache-error"));
    s.on_next(generate("logcollector", "expected"));
    s.on_next(generate("logcollector", "apache-access"));
    s.on_next(generate("logcollector", "apache-error"));
    s.on_completed();
};

json::Document generate_decoder(const string & name, const vector<string> & parents, const map<string, string> & check,
                                const map<string, string> & normalize)
{
    auto j_name = "\"name\": \"" + name + "\"";

    string parents_string = "[";
    for_each(parents.begin(), parents.end() - 1,
             [&parents_string](auto parent) { parents_string += "\"" + parent + "\", "; });
    parents_string += "\"" + parents.back() + "\"]";
    auto j_parents = "\"parents\":" + parents_string;

    string check_string;
    for_each(check.begin(), check.end(),
             [&check_string](auto _check) { check_string += "\"" + _check.first + "\": \"" + _check.second + "\", "; });
    check_string.pop_back();
    check_string.pop_back();
    auto j_check = "\"check\":{" + check_string + "}";

    string normalize_string;
    for_each(normalize.begin(), normalize.end(),
             [&normalize_string](auto _normalize)
             { normalize_string += "\"" + _normalize.first + "\": \"" + _normalize.second + "\", "; });
    normalize_string.pop_back();
    normalize_string.pop_back();
    auto j_normalize = "\"normalize\":{" + normalize_string + "}";

    string j_string = "{" + j_name + "," + j_parents + "," + j_check + "," + j_normalize + "}";

    return json::Document{j_string.c_str()};
}

json::Document generate_pair(const string & name, const string & value)
{
    string j_string = "{\"" + name + "\": " + "\"" + value + "\"}";
    return json::Document{j_string.c_str()};
}

#endif //_TEST_UTILS_H
