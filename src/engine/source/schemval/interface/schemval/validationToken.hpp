#ifndef _SCHEMVAL_VALIDATIONTOKEN_HPP
#define _SCHEMVAL_VALIDATIONTOKEN_HPP

#include <variant>

#include <json/json.hpp>
#include <schemf/ischema.hpp>

namespace schemval
{

constexpr size_t IS_JTYPE = 0;
constexpr size_t IS_STYPE = 1;
constexpr size_t IS_VALUE = 2;
constexpr size_t IS_NONE = 3;

class ValidationToken
{
private:
    struct None
    {
    };
    using TokenT = std::variant<json::Json::Type, schemf::Type, json::Json, None>;

    TokenT m_token;
    bool m_needsRuntimeValidation;
    bool m_isArray;

public:
    explicit ValidationToken(json::Json::Type type, bool isArray = false)
        : m_token(type)
        , m_needsRuntimeValidation(true)
        , m_isArray(isArray)
    {
    }
    explicit ValidationToken(schemf::Type type, bool isArray = false)
        : m_token(type)
        , m_needsRuntimeValidation(false)
        , m_isArray(isArray)
    {
    }
    explicit ValidationToken(json::Json value)
        : m_token(value)
        , m_needsRuntimeValidation(false)
        , m_isArray(value.isArray())
    {
    }

    ValidationToken()
        : m_token(None())
        , m_needsRuntimeValidation(true)
        , m_isArray(false)
    {
    }

    ValidationToken(const ValidationToken& other) = default;
    ValidationToken& operator=(const ValidationToken& other)
    {
        m_token = std::variant(other.m_token);
        m_needsRuntimeValidation = other.m_needsRuntimeValidation;
        m_isArray = other.m_isArray;

        return *this;
    }

    inline const TokenT& getToken() const { return m_token; }

    inline bool needsRuntimeValidation() const { return m_needsRuntimeValidation; }
    inline bool isArray() const { return m_isArray; }

    inline size_t which() const { return m_token.index(); }
};

} // namespace schemval

#endif // _SCHEMVAL_VALIDATIONTOKEN_HPP
