#include "registry.hpp"

#include <string>

#include "builder.hpp"


using namespace std;

namespace builder
{
    Registry& Registry::instance()
    {
        static Registry instance;
        return instance;
    }

    void Registry::register_builder(const string& builder_id, const Builder& builder)
    {
        if (registry.count(builder_id)>0) {
            throw invalid_argument("Key is already stored on the map");
        }else{
            this->registry[builder_id] = &builder;
        }
    }

    const Builder* Registry::get_builder(const string& builder_id) const
    {
        return this->registry.at(builder_id);
    }
}
