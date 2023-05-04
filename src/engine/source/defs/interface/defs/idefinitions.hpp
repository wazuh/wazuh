#ifndef _DEFS_IDEFINITIONS_HPP
#define _DEFS_IDEFINITIONS_HPP

#include <json/json.hpp>

namespace defs
{
    class IDefinitions
    {
    public:
        virtual ~IDefinitions() = default;

        virtual json::Json get(std::string_view name) const = 0;

        virtual bool contains(std::string_view name) const = 0;
    };
}

#endif // _DEFS_IDEFINITIONS_HPP
