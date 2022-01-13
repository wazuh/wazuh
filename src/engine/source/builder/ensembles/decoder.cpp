#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>
#include <string>

#include "builder.hpp"
#include "connectable.hpp"
#include "json.hpp"
#include "registry.hpp"
#include "utils.hpp"

using namespace std;
using namespace rxcpp;
using namespace builder::internals;
using json = builder::shared::Json;

namespace {

typedef Connectable<subscriber<json>, observable<json>> connectable_type;
typedef Builder<connectable_type(json)> decoder_type;
typedef Builder<observable<json>(observable<json>, json)> check_type;

/**********************************************************************************************/
// Decoder builder
/**********************************************************************************************/
string s_decoderName("decoder");

connectable_type decoderBuild(const json &inputJson) {
  auto subj = subjects::subject<json>();
  auto output = subj.get_observable();
  auto input = subj.get_subscriber();

  auto checkBuilder = Registry::instance().builder<check_type>("decoder.check");
  output = checkBuilder(output, inputJson.get(".check");

  return Connectable(inputJson.get(".name").to_string(), input, output);
}

Registry::instance().registerBuilder<decoder_type>(s_decoderName,
                                                   decoder_type{s_decoderName,
                                                                decoderBuild});

/**********************************************************************************************/
// Check stage builder
/**********************************************************************************************/
string checkName("decoder.check");
observable<json> check_build(const observable<json> &input_observable,
                             const json &input_json) {
  // Check that input is as expected and throw exception otherwise
  if (!input_json.is_array()) {
    throw builder::BuildError(decoder_name, "build expects json with an array");
  }

  builder::Registry &registry = builder::Registry::instance();

  auto output_observable = input_observable;
  for (auto j_obj : input_json) {
    auto _builder = static_cast<const builder::JsonBuilder *>(
        registry.get_builder("condition"));
    output_observable = _builder->build(output_observable, j_obj);
  }

  return output_observable;
}

builder::JsonBuilder check_builder(check_name, check_build);
} // namespace
