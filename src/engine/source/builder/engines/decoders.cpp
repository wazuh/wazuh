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
    string name("decoders");
    observable<json> build(const observable<json>& input_observable, const vector<json>& input_jsons)
    {

        return input_observable;
    }

    builder::MultiJsonBuilder decoder_builder(name, build);
}
