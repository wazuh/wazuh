#include <string>
#include <rxcpp/rx.hpp>

#include "builder.hpp"
#include "utils.hpp"
#include "json.hpp"

#include "rapidjson/document.h"
#include "rapidjson/pointer.h"

using namespace std;
using namespace rxcpp;

namespace
{
    string name("map.value");
    observable<json::Document> build(const observable<json::Document> &input_observable,
                                     const rapidjson::Value &input_json)
    {
        auto iter = input_json.MemberBegin();
        auto output_observable = input_observable.map([iter](json::Document e)
        {

            e.set(iter->name.GetString(),iter->value);

            return e;

        });
        return output_observable;
    }

    builder::internals::Builder<observable<json::Document>(observable<json::Document>,
                                       rapidjson::Value)>
    map_value(name, build);
}
