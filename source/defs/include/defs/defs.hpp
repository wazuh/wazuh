#ifndef _DEFS_HPP_
#define _DEFS_HPP_

#include <string>
#include <string_view>

#include <json/json.hpp>
#include <defs/iDefinitions.hpp>

namespace defs
{
class Definitions : public IDefinitions
{
private:
    json::Json m_definitions;

public:
    /**
     * @brief Construct a new Definitions object
     *
     * @param definitions JSON object containing definitions
     * @throw std::runtime_error if definitions is not an object or is empty, or if a definition is invalid
     */
    explicit Definitions(const json::Json& definitions);

    Definitions() = default;
    ~Definitions() = default;

    /**
     * @brief Get the definitions json object
     *
     * @return const json::Json&
     */
    const json::Json& get() const;
};
} // namespace defs

#endif // _DEFS_HPP_
