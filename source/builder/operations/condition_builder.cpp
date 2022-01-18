#include <rxcpp/rx.hpp>
#include <string>

#include "asset_builder.hpp"
#include "json.hpp"
#include "registry.hpp"
#include "syntax.hpp"

using namespace std;
using namespace rxcpp;
using namespace builder::internals;

using event_t = json::Document;
using value_t = const json::Value *;
using condition_builder_t =
    AssetBuilder<observable<event_t>(observable<event_t>, value_t)>;

namespace {
observable<event_t> build(const observable<event_t> &input_observable,
                          value_t input_json) {
  // Check that input is as expected and throw exception otherwise
  if (!input_json->IsObject()) {
    throw invalid_argument(
        "condition build expects json with an object, but got " +
        input_json->GetType());
  }

  if (input_json->GetObject().MemberCount() != 1) {
    throw invalid_argument(
        "condition build expects json with only one key, but got" +
        input_json->GetObject().MemberCount());
  }

  value_t value = &input_json->MemberBegin()->value;

  observable<event_t> output_observable;

  // Deduce builder from value anchors, only if it is string
  if (value->IsString()) {
    string str_value = value->GetString();

    if (str_value.compare(0, syntax::REFERENCE_ANCHOR.size(),
                          syntax::REFERENCE_ANCHOR) == 0) {
      /* TODO */
    } else if (str_value.compare(0, syntax::HELPER_ANCHOR.size(),
                                 syntax::HELPER_ANCHOR) == 0) {
      output_observable = Registry::instance().builder<condition_builder_t>(
          "condition." + str_value.replace(0, syntax::HELPER_ANCHOR.size(), ""))(
          input_observable, input_json);

    } else {
      output_observable = Registry::instance().builder<condition_builder_t>(
          "condition.value")(input_observable, input_json);
    }
  } else if (value->IsArray()) {
    /* TODO */
  } else {
    output_observable = Registry::instance().builder<condition_builder_t>(
        "condition.value")(input_observable, input_json);
  }

  return output_observable;
}

condition_builder_t conditionBuilder("condition", build);
} // namespace
