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
    /**********************************************************************************************/
    /* Helper exists
    /**********************************************************************************************/
    string name_exists("helper.exists");
    observable<json> build_exists(const observable<json>& input_observable, const json& input_json)
    {
        // Check that input is as expected and throw exception otherwise
        if (!input_json.is_object())
        {
            throw builder::BuildError(name_exists, "build expects json with an object");
        }

        if (input_json.size() != 1)
        {
            throw builder::BuildError(name_exists, "build expects json with only one key");
        }

        auto it = begin(input_json);
        auto field =  builder::utils::JsonPath(it.key());
        // Todo validate json path
        // value is ignored
        // auto value = it.value();
        auto output_observable = input_observable.filter([field](json e)
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

            return true;
        });
        return output_observable;
    }

    builder::JsonBuilder helper_exists_builder(name_exists, build_exists);


    /**********************************************************************************************/
    /* Helper not_exists
    /**********************************************************************************************/
    string name_not_exists("helper.not_exists");
    observable<json> build_not_exists(const observable<json>& input_observable, const json& input_json)
    {
        // Check that input is as expected and throw exception otherwise
        if (!input_json.is_object())
        {
            throw builder::BuildError(name_not_exists, "build expects json with an object");
        }

        if (input_json.size() != 1)
        {
            throw builder::BuildError(name_not_exists, "build expects json with only one key");
        }

        auto it = begin(input_json);
        auto field =  builder::utils::JsonPath(it.key());
        // Todo validate json path
        // value is ignored
        // auto value = it.value();
        auto output_observable = input_observable.filter([field](json e)
        {
            const json* actual = &e;

            for (auto field_name : field)
            {

                if (actual->contains(field_name))
                {
                    return false;
                }
                else
                {
                    actual = &(*actual)[field_name];
                }
            }

            return true;
        });
        return output_observable;
    }

    builder::JsonBuilder helper_not_exists_builder(name_not_exists, build_not_exists);
}
