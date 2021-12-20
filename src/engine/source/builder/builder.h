#pragma once

#include <string_view>
#include <rxcpp/rx.hpp>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;

namespace builder{
    rxcpp::observable<json> get_enviroment(const string_view&);
    typedef rxcpp::observable<json> builder (rxcpp::observable<json>, const json&);
};
