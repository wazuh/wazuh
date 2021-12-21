#include "builder.h"

#include <rxcpp/rx.hpp>
#include <string_view>
#include <nlohmann/json.hpp>

#include "registry.h"

using json = nlohmann::json;
using namespace std;
using namespace rxcpp;

namespace builder
{
    Builder::Builder(const string& builder_id)
    {
        Registry& registry = Registry::instance();
        registry.register_builder(builder_id, *this);
    }

    JsonBuilder::JsonBuilder(const string& builder_id, observable<json> (*build)(const observable<json>&, const json&)): Builder(builder_id), build(build) {}

    MultiJsonBuilder::MultiJsonBuilder(const string& builder_id, observable<json> (*build)(const observable<json>& obs, const vector<json>&)): Builder(builder_id), build(build) {}
}
