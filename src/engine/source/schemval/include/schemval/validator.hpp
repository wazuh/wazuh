#ifndef _SCHEMVAL_VALIDATOR_HPP
#define _SCHEMVAL_VALIDATOR_HPP

#include <unordered_map>

#include <fmt/format.h>
#include <schemf/ischema.hpp>

#include <schemval/ivalidator.hpp>

namespace schemval
{

// TODO allow for validators associated to a field instead of a type

class Validator final : public IValidator
{
private:
    /**
     * @brief Holds the parser builder and json type for a schema type.
     *
     */
    struct Entry
    {
        RuntimeValidator validator; ///< Parser builder for the schema type.
        json::Json::Type jsonType; ///< Json type for the schema type.
    };

    std::unordered_map<schemf::Type, Entry> m_entries; ///< Map of schema types to their parser and json type.
    std::shared_ptr<schemf::ISchema> m_schema;         ///< Schema to validate against.

    /**
     * @brief Get the Entry object
     *
     * @param type Schema type.
     * @return const Entry&
     *
     * @throw std::runtime_error if the type is not in the map.
     */
    inline const Entry& getEntry(schemf::Type type) const
    {
        auto it = m_entries.find(type);
        if (it == m_entries.end())
        {
            throw std::runtime_error(
                fmt::format("Schema validator does not have a validator for type {}", schemf::typeToStr(type)));
        }

        return it->second;
    }

public:
    explicit Validator(const std::shared_ptr<schemf::ISchema>& schema);
    ~Validator() = default;

    /**
     * @brief Check if the given schema type is compatible with the given json type.
     *
     * @param sType
     * @param jType
     * @return true
     * @return false
     */
    inline bool isCompatible(schemf::Type sType, json::Json::Type jType) const { return getEntry(sType).jsonType == jType; }

    /**
     * @copydoc IValidator::getJsonType
     */
    inline json::Json::Type getJsonType(schemf::Type type) const override { return getEntry(type).jsonType; }

    /**
     * @copydoc IValidator::validate
     */
    base::OptError validate(const DotPath& destPath, const json::Json::Type& type) const override;

    /**
     * @copydoc IValidator::validate
     */
    base::OptError validate(const DotPath& destPath, const DotPath& sourcePath) const override;

    /**
     * @copydoc IValidator::getRuntimeValidator
     */
    base::RespOrError<RuntimeValidator> getRuntimeValidator(const DotPath& destPath) const override;
};

} // namespace schemval

#endif // _SCHEMVAL_VALIDATOR_HPP
