#include "builder.hpp"

#include <string>
#include <rxcpp/rx.hpp>
#include <nlohmann/json.hpp>

#include "registry.hpp"


using json = nlohmann::json;
using namespace std;
using namespace rxcpp;

namespace builder
{
    /**********************************************************************************************/
    /* Builder classes                                                                            */
    /**********************************************************************************************/
    Builder::Builder(const string& builder_id)
    {
        Registry& registry = Registry::instance();
        registry.register_builder(builder_id, *this);
    }

    JsonBuilder::JsonBuilder(const string& builder_id, observable<json> (*build)(const observable<json>&, const json&)): Builder(builder_id), build(build) {}

    MultiJsonBuilder::MultiJsonBuilder(const string& builder_id, observable<json> (*build)(const observable<json>& obs, const vector<json>&)): Builder(builder_id), build(build) {}

    /**********************************************************************************************/
    /* BuildError class                                                                           */
    /**********************************************************************************************/
    BuildError::BuildError(const string& builder_name, const string& message): m_builder_name{move(builder_name)}, m_message{move(message)} {}

    const char* BuildError::what() const noexcept
    {
        return this->m_message.c_str();
    }
}
