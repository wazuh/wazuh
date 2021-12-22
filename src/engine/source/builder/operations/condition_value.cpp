#include <string>
#include <nlohmann/json.hpp>
#include <rxcpp/rx.hpp>

#include "builder.hpp"
#include "utils.hpp"


using json = nlohmann::json;
using namespace std;
using namespace rxcpp;

namespace
{
    string name("condition.value");
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
        auto output_observable = input_observable.filter([field, value](json e)
        {
            const json* actual = &e;

            for (auto field_name : field)
            {

                if (!actual->contains(field_name))
                {
                    return false;
                }
                else
                {
                    actual = &(*actual)[field_name];
                }
            }

            return *actual == value;
        });
        return output_observable;
    }

    builder::JsonBuilder condition_value_builder(name, build);
}
