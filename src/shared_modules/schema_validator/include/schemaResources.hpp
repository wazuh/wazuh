#ifndef _SCHEMA_RESOURCES_HPP
#define _SCHEMA_RESOURCES_HPP

#include <map>
#include <string>

namespace SchemaValidator
{
    namespace Resources
    {
        /**
         * @brief Get embedded schema resources
         *
         * @return const std::map<std::string, std::string>& Map of filename -> JSON content
         */
        const std::map<std::string, std::string>& getEmbeddedSchemas();

    } // namespace Resources
} // namespace SchemaValidator

#endif // _SCHEMA_RESOURCES_HPP
