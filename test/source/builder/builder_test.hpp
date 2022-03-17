
#ifndef _BUILDER_TEST_H
#define _BUILDER_TEST_H

#include "connectable.hpp"
#include "rxcpp/rx.hpp"
#include "json/json.hpp"
#include <hlp/hlp.hpp>

std::map<std::string, std::string> decoders = {{"decoder_0", R"(
                {
                    "name": "decoder_0",
                    "check": [
                        {"type": "int"}
                    ],
                    "normalize": [
                        { "new_dec_field0": "new_dec_value0" }
                    ]
                }
    )"},
                                               {"decoder_1", R"(
                {
                    "name": "decoder_1",
                    "parents": [
                        "decoder_0"
                    ],
                    "check": [
                        {"field": "odd"}
                    ],
                    "normalize": [
                        { "new_dec_field1": "new_dec_value1" }
                    ]
                }
    )"},
                                               {"decoder_2", R"(
                {
                    "name": "decoder_2",
                    "parents": [
                        "decoder_0"
                    ],
                    "check": [
                        {"field": "even"}
                    ],
                    "normalize": [
                        { "new_dec_field2": "new_dec_value2" }
                    ]
                }
    )"},
                                               {"decoder_3", R"(
                {
                    "name": "decoder_3",
                    "parents": [
                        "decoder_1",
                        "decoder_2"
                    ],
                    "check": [
                        {"type": "int"}
                    ],
                    "normalize": [
                        { "new_dec_field3": "new_dec_value3" }
                    ]
                }
    )"}};

std::map<std::string, std::string> rules = {{"rule_0", R"(
                    {
                    "name": "rule_0",
                    "check": [
                        {"type": "int"}
                    ],
                    "normalize": [
                        { "new_rule_field": "new_rule_value" }
                    ]
                }
    )"}};

std::map<std::string, std::string> filters = {{"filter_0", R"(
                {
                    "name": "filter_0",
                    "after": [
                        "rule_0"
                    ],
                    "allow": [
                        {"type": "int"}
                    ]
                }
    )"}};

std::map<std::string, std::string> outputs = {{"output_0", R"(
                {
                    "name": "fileOutput",
                    "check": [
                        {"type": "int"}
                    ],
                    "outputs": [
                        {"file": { "path": "/tmp/filepath.txt" }}
                    ]
                }
    )"}};

std::map<std::string, std::string> environments = {
    {"environment_1", R"( { "decoders": [ "decoder_0"] })"},
    {"environment_2", R"( { "decoders": [ "decoder_0"], "rules": [ "rule_0" ] })"},
    {"environment_3", R"( { "decoders": [ "decoder_0"], "rules": [ "rule_0" ], "filters": [ "filter_0" ] })"},
    {"environment_4",
     R"({  "decoders": [ "decoder_0" ], "rules": [ "rule_0" ], "filters": [ "filter_0" ], "outputs": [ "output_0" ] })"},
    {"environment_5", R"({
     "decoders": [ "decoder_0" , "decoder_1" ],
     "rules": [ "rule_0" ],
     "filters": [  ],
     "outputs": [ "output_0" ]
     })"},
    {"environment_6", R"({
     "decoders": [ "decoder_0" , "decoder_1" , "decoder_2", "decoder_3" ],
     "rules": [ "rule_0" ],
     "filters": [ "filter_0" ],
     "outputs": [ "output_0" ]
     })"}};

class FakeCatalog
{
private:
public:
    json::Document getAsset(const std::string atype, const std::string assetName) const
    {

        if (atype == "environment")
        {
            return json::Document(environments[assetName].c_str());
        }

        if (atype == "decoder")
        {
            return json::Document(decoders[assetName].c_str());
        }

        if (atype == "rule")
        {
            return json::Document(rules[assetName].c_str());
        }

        if (atype == "filter")
        {
            return json::Document(filters[assetName].c_str());
        }

        if (atype == "output")
        {
            return json::Document(outputs[assetName].c_str());
        }

        throw std::invalid_argument("fakeCatalog does not support asset type " + atype);
    }

    std::vector<std::string> getAssetList(const std::string)
    {
        throw std::runtime_error("not implemented");
        return {"not", "implemented"};
    }
};

#endif // _BUILDER_TEST_H
