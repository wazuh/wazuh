#ifndef _DEFS_HPP_
#define _DEFS_HPP_

#include <memory>
#include <string>
#include <string_view>

#include <defs/idefinitions.hpp>
#include <json/json.hpp>

namespace defs
{
class Definitions : public IDefinitions
{
private:
    std::unique_ptr<json::Json> m_definitions;

public:
    Definitions() = default;
    ~Definitions() = default;

    /**
     * @brief Construct a new Definitions object
     *
     * @param definitions JSON object containing definitions
     * @throw std::runtime_error if definitions is not an object or is empty, or if a definition is invalid
     */
    explicit Definitions(const json::Json& definitions);

    bool contains(std::string_view name) const override;

    /**
     * @brief Get the definitions json object
     *
     * @return const json::Json&
     */
    json::Json get(std::string_view name) const override;
};
} // namespace defs

#endif // _DEFS_HPP_
