#include <memory>
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
observable<event_t> build(const observable<event_t> &input_observable,
                          value_t input_json) {
  auto valDoc = json::Document(*input_json);

  auto output_observable =
      input_observable.filter([valDoc](event_t e) { return e.check(valDoc); });
  return output_observable;
}

AssetBuilder<observable<event_t>(observable<event_t>, value_t)>
    condition_value("condition.value", build);
} // namespace
