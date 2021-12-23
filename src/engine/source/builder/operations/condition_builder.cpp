#include <string>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>

#include "builder.hpp"
#include "registry.hpp"
#include "syntax.hpp"
#include "utils.hpp"


using json = nlohmann::json;
using namespace std;
using namespace rxcpp;

namespace
{
    string name("condition");
    observable<json> build(const observable<json>& input_observable, const json& input_json)
    {
        // Check that input is as expected and throw exception otherwise
        if (!input_json.is_object())
        {
            throw builder::BuildError(name, "build expects json with an object");
        }

        if (input_json.size() != 1)
        {
            throw builder::BuildError(name, "build expects json with only one key");
        }

        auto it = begin(input_json);
        auto field =  builder::utils::JsonPath(it.key());
        // Todo validate json path
        auto value = it.value();
        builder::Registry& registry = builder::Registry::instance();

        observable<json> output_observable;

        // Deduce builder from value anchors, only if it is string
        if (value.is_string())
        {
            auto str_value = value.get<string>();

            if (str_value.compare(0, builder::syntax::REFERENCE_ANCHOR.size(), builder::syntax::REFERENCE_ANCHOR) == 0)
            {
                /* TODO */
            }
            else if (str_value.compare(0, builder::syntax::HELPER_ANCHOR.size(), builder::syntax::HELPER_ANCHOR) == 0)
            {
                output_observable = static_cast<const builder::JsonBuilder*>(registry.get_builder("helper."+str_value.replace(0, builder::syntax::HELPER_ANCHOR.size(), "")))->build(input_observable, input_json);
            }
            else
            {
                output_observable = static_cast<const builder::JsonBuilder*>(registry.get_builder("condition.value"))->build(input_observable, input_json);
            }
        }
        else
        {
            output_observable = static_cast<const builder::JsonBuilder*>(registry.get_builder("condition.value"))->build(input_observable, input_json);
        }

        return output_observable;
    }

    builder::JsonBuilder condition_builder(name, build);
}
