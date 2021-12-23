#include <string>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>

#include "builder.hpp"
#include "registry.hpp"
#include "utils.hpp"


using json = nlohmann::json;
using namespace std;
using namespace rxcpp;

namespace
{
    /**********************************************************************************************/
    // Decoder builder
    /**********************************************************************************************/
    string decoder_name("decoder");
    observable<json> decoder_build(const observable<json>& input_observable, const json& input_json)
    {
        // Check that input is as expected and throw exception otherwise
        if (!input_json.is_object())
        {
            throw builder::BuildError(decoder_name, "build expects json with an object");
        }

        // Metadata, TODO

        builder::Registry& registry = builder::Registry::instance();
        auto output_observable = input_observable;
        // Check stage
        if (!input_json.contains("check"))
        {
            throw builder::BuildError(decoder_name, "build stage check not found");
        }
        else
        {
            auto _builder = static_cast<const builder::JsonBuilder*>(registry.get_builder("decoder.check"));
            output_observable = _builder->build(output_observable, input_json["check"]);
        }

        return output_observable;
    }

    builder::JsonBuilder decoder_builder(decoder_name, decoder_build);

    /**********************************************************************************************/
    // Check stage builder
    /**********************************************************************************************/
    string check_name("decoder.check");
    observable<json> check_build(const observable<json>& input_observable, const json& input_json)
    {
        // Check that input is as expected and throw exception otherwise
        if (!input_json.is_array())
        {
            throw builder::BuildError(decoder_name, "build expects json with an array");
        }

        builder::Registry& registry = builder::Registry::instance();

        auto output_observable = input_observable;
        for (auto j_obj : input_json){
            auto _builder = static_cast<const builder::JsonBuilder*>(registry.get_builder("condition"));
            output_observable = _builder->build(output_observable, j_obj);
        }

        return output_observable;
    }

    builder::JsonBuilder check_builder(check_name, check_build);
}
