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
         * @brief Get the definition json with the given dot path name.
         *
         * @param name Dot path name of the definition.
         * @return json::Json value of the definition.
         *
         * @throws std::runtime_error if the definition does not exist.
         */
        virtual json::Json get(std::string_view name) const = 0;

        /**
         * @brief Check if the definition exists.
         *
         * @param name Dot path name of the definition.
         * @return true
         * @return false
         */
        virtual bool contains(std::string_view name) const = 0;
    };
}

#endif // _DEFS_IDEFINITIONS_HPP
