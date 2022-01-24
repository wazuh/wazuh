
#include "connectable.hpp"
#include "rxcpp/rx.hpp"
#include "json/json.hpp"

std::map<std::string, std::string> decoders = {{"decoder_0", R"(
                {
                    "name": "decoder_0",
                    "check": [
                        {"field": "value" }
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
                        {"field": "value" }
                    ],
                    "normalize": [
                        { "new_dec_field1": "new_dec_value1" }
                    ]
                }
    )"}};

std::map<std::string, std::string> rules = {{"rule_0", R"(
                    {
                    "name": "rule_0",
                    "check": [
                        {"field": "value"}
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
                        "decoder_1"
                    ],
                    "allow": [
                        {"field": "value"}
                    ]
                }
    )"}};

std::map<std::string, std::string> outputs = {{"output_0", R"(
                {
                    "name": "output_0",
                    "check": [
                        {"field": "value"}
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
     R"({  "decoders": [ "decoder_0" , "decoder_1" ], "rules": [ "rule_0" ], "filters": [ "filter_0" ], "outputs": [ "output_0" ] })"},
};

class FakeCatalog
{
private:
public:
    json::Document getAsset(const std::string atype, const std::string assetName)
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
