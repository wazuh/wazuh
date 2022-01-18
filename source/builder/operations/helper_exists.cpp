#include <rxcpp/rx.hpp>
#include <string>

#include "asset_builder.hpp"
#include "json.hpp"

using namespace std;
using namespace rxcpp;
using namespace builder::internals;

using event_t = json::Document;
using value_t = const json::Value *;

namespace {

/**********************************************************************************************/
/* Helper exists
/**********************************************************************************************/
observable<event_t> buildExists(const observable<event_t> &input_observable,
                                value_t input_json) {
  string field = "/";
  field += input_json->MemberBegin()->name.GetString();

  auto output_observable =
      input_observable.filter([field](event_t e) { return e.check(field); });
  return output_observable;
}

AssetBuilder<observable<event_t>(observable<event_t>, value_t)>
    conditionExists("condition.exists", buildExists);

/**********************************************************************************************/
/* Helper not_exists
/**********************************************************************************************/
observable<event_t> buildNotExists(const observable<event_t> &input_observable,
                                   value_t input_json) {
  string field = "/";
  field += input_json->MemberBegin()->name.GetString();

  auto output_observable =
      input_observable.filter([field](event_t e) { return !e.check(field); });
  return output_observable;
}

AssetBuilder<observable<event_t>(observable<event_t>, value_t)>
    conditionNotExists("condition.not_exists", buildNotExists);

} // namespace
