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
    string name("map.reference");
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
        auto reference = builder::utils::JsonPath(it.value());
        // Todo validate json path
        auto output_observable = input_observable.map([field, reference](json e)
        {
            //Find referenced value
            const json* finder = &e;

            for (auto reference_it=reference.begin() ; reference_it<reference.end() ; ++reference_it ){

                string field_value = *reference_it;

                if (finder->contains(field_value))
                {
                    finder = &(*finder)[field_value];
                }

            }

            nlohmann::basic_json value = *finder;

            //Map referenced value
            json* actual = &e;

            for (auto field_it=field.begin() ; field_it<field.end()-1 ; ++field_it ){

                string field_name = *field_it;

                if (actual->contains(field_name))
                {
                    actual = &(*actual)[field_name];
                }

            }
            
            (*actual)[*(field.end()-1)] = value;

            return e;
        });
        return output_observable;
    }

    builder::JsonBuilder map_reference_builder(name, build);
}
