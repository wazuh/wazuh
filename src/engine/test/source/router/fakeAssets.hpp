#ifndef _STORE_TEST_FAKE_ASSETS_H
#define _STORE_TEST_FAKE_ASSETS_H

#include <map>
#include <string>
#include <vector>

namespace aux
{
auto constexpr DEC_1 = R"e({
    "name": "decoder/deco_1/0",
    "metadata": {
        "description": "Queue 45/50"
    },
    "check": "exists($wazuh.queue) AND ( int_equal($wazuh.queue,49) OR int_equal($wazuh.queue,50) )",
    "normalize": [
        {
            "map": [
                {
                    "~decoder": "deco_1"
                }
            ]
        }
    ]
})e";

auto constexpr DEC_2 = R"e({
    "name": "decoder/deco_2/0",
    "metadata": {
        "description": "Queue 45/50"
    },
    "check": "exists($wazuh.queue) AND ( int_equal($wazuh.queue,51) OR int_equal($wazuh.queue,52) )",
    "normalize": [
        {
            "map": [
                {
                    "~decoder": "deco_2"
                }
            ]
        }
    ]
})e";

auto constexpr DEC_3 = R"e({
    "name": "decoder/deco_3/0",
    "metadata": {
        "description": "Queue 45/50"
    },
    "check": "exists($wazuh.queue) AND ( int_less($wazuh.queue,49) OR int_greater($wazuh.queue,52) )",
    "normalize": [
        {
            "map": [
                {
                    "~decoder": "deco_3"
                }
            ]
        }
    ]
})e";

auto constexpr DEC_A1 = R"e({
    "name": "decoder/deco_A1/0",
    "metadata": {
        "description": "Allow all set ~decoder to deco_A1 "
    },
    "check": [
        {
            "wazuh.queue": "exists()"
        }
    ],
    "normalize": [
        {
            "map": [
                {
                    "~decoder": "deco_A1"
                }
            ]
        }
    ]
})e";

auto constexpr DEC_B2 = R"e({
    "name": "decoder/deco_B2/0",
    "metadata": {
        "description": "Allow all set ~decoder to deco_B2 "
    },
    "check": [
        {
            "wazuh.queue": "exists()"
        }
    ],
    "normalize": [
        {
            "map": [
                {
                    "~decoder": "deco_B2"
                }
            ]
        }
    ]
})e";

auto constexpr DEC_C3 = R"e({
    "name": "decoder/deco_C3/0",
    "metadata": {
        "description": "Allow all set ~decoder to deco_C3 "
    },
    "check": [
        {
            "wazuh.queue": "exists()"
        }
    ],
    "normalize": [
        {
            "map": [
                {
                    "~decoder": "deco_C3"
                }
            ]
        }
    ]
})e";

auto constexpr FIL_ALL = R"e({
    "name": "filter/allow_all/0"
})e";

auto constexpr FIL_A1 = R"e({
    "name": "filter/allow_all_A1/0"
})e";

auto constexpr FIL_B2 = R"e({
    "name": "filter/allow_all_B2/0"
})e";

auto constexpr FIL_C3 = R"e({
    "name": "filter/allow_all_C3/0"
})e";

auto constexpr FIL_E_WAZUH_QUEUE = R"e({
    "name": "filter/e_wazuh_queue/0",
    "check": [
        {
            "wazuh.queue": "exists()"
        },
        {
            "wazuh.no_queue": "exists()"
        }
    ]
})e";

auto constexpr INTERNAL_ROUTE_TABLE = R"e([
    {
        "name": "allow_all_C3",
        "priority": 1,
        "filter": "filter/allow_all_C3/0",
        "target": "policy/pol_C3/0"
    },
    {
        "name": "allow_all_A1",
        "priority": 50,
        "filter": "filter/allow_all_A1/0",
        "target": "policy/pol_A1/0"
    },
    {
        "name": "allow_all_B2",
        "priority": 202,
        "filter": "filter/allow_all_B2/0",
        "target": "policy/pol_B2/0"
    }
])e";

auto constexpr POLICY_1 = R"e({
    "name": "policy/pol_1/0",
    "decoders": [
        "decoder/deco_1/0",
        "decoder/deco_2/0",
        "decoder/deco_3/0"
    ]
})e";

auto constexpr POLICY_2 = R"e({
    "name": "policy/pol_2/0",
    "decoders": [
        "decoder/deco_1/0",
        "decoder/deco_2/0",
        "decoder/deco_3/0"
    ]
})e";

auto constexpr POLICY_3 = R"e({
    "name": "policy/pol_3/0",
    "decoders": [
        "decoder/deco_1/0",
        "decoder/deco_2/0",
        "decoder/deco_3/0"
    ]
})e";

auto constexpr POLICY_A1 = R"e({
    "name": "policy/pol_A1/0",
    "decoders": [
        "decoder/deco_A1/0"
    ]
})e";

auto constexpr POLICY_B2 = R"e({
    "name": "policy/pol_B2/0",
    "decoders": [
        "decoder/deco_B2/0"
    ]
})e";

auto constexpr POLICY_C3 = R"e({
    "name": "policy/pol_C3/0",
    "decoders": [
        "decoder/deco_C3/0"
    ]
})e";

static std::map<std::string, const char*> assets = {{"decoder/deco_1/0", DEC_1},
                                                    {"decoder/deco_2/0", DEC_2},
                                                    {"decoder/deco_3/0", DEC_3},
                                                    {"decoder/deco_A1/0", DEC_A1},
                                                    {"decoder/deco_B2/0", DEC_B2},
                                                    {"decoder/deco_C3/0", DEC_C3},
                                                    {"filter/allow_all/0", FIL_ALL},
                                                    {"filter/allow_all_A1/0", FIL_A1},
                                                    {"filter/allow_all_B2/0", FIL_B2},
                                                    {"filter/allow_all_C3/0", FIL_C3},
                                                    {"filter/e_wazuh_queue/0", FIL_E_WAZUH_QUEUE},
                                                    {"policy/pol_1/0", POLICY_1},
                                                    {"policy/pol_2/0", POLICY_2},
                                                    {"policy/pol_3/0", POLICY_3},
                                                    {"policy/pol_A1/0", POLICY_A1},
                                                    {"policy/pol_B2/0", POLICY_B2},
                                                    {"policy/pol_C3/0", POLICY_C3},
                                                    {"internal/router_table/0", INTERNAL_ROUTE_TABLE}};

static std::map<std::string, std::vector<std::string>> policies = {
    {"policy/pol_1/0", {"policy/pol_1/0", "decoder/deco_1/0", "decoder/deco_2/0", "decoder/deco_3/0"}},
    {"policy/pol_2/0", {"policy/pol_2/0", "decoder/deco_1/0", "decoder/deco_2/0", "decoder/deco_3/0"}},
    {"policy/pol_3/0", {"policy/pol_3/0", "decoder/deco_1/0", "decoder/deco_2/0", "decoder/deco_3/0"}},
    {"policy/pol_A1/0", {"policy/pol_A1/0", "decoder/deco_A1/0"}},
    {"policy/pol_B2/0", {"policy/pol_B2/0", "decoder/deco_B2/0"}},
    {"policy/pol_C3/0", {"policy/pol_C3/0", "decoder/deco_C3/0"}}};

static std::map<std::string, std::pair<std::vector<std::string>, std::vector<std::string>>> tables = {
    {"internal/router_table/0",
     {{"filter/allow_all_C3/0", "filter/allow_all_A1/0", "filter/allow_all_B2/0"},
      {"policy/pol_C3/0", "policy/pol_A1/0", "policy/pol_B2/0"}}}};

} // namespace aux

#endif // _STORE_TEST_FAKE_ASSETS_H
