#ifndef _DEFS_IDEFINITIONS_HPP
#define _DEFS_IDEFINITIONS_HPP

#include <json/json.hpp>

namespace defs
{
    class IDefinitions
    {
    public:
        virtual ~IDefinitions() = default;

        /**
         * @brief Get the definitions json object
         *
         * @return const json::Json&
         */
        virtual const json::Json& get() const = 0;
    };
}

#endif // _DEFS_IDEFINITIONS_HPP
