#include <defs/idefinitions.hpp>

namespace defs::mocks
{
class SingleDef : public IDefinitions
{
private:
    std::string m_name;
    json::Json m_value;

public:
    SingleDef() = default;
    ~SingleDef() = default;

    json::Json get(std::string_view dotName) const override
    {
        if (SingleDef::dotPathName() == dotName)
        {
            return value();
        }

        throw std::runtime_error("Invalid definition name");
    }
    bool contains(std::string_view dotName) const override { return SingleDef::dotPathName() == dotName; }
    std::string replace(std::string_view input) const override { return std::string(input); }

    static std::string name() { return "SingleDef"; }
    static std::string dotPathName() { return "/SingleDef"; }
    static std::string referenceName() { return "$SingleDef"; }
    static json::Json value() { return json::Json(R"("SingleDef")"); }
    static std::string strValue() { return "SingleDef"; }
};
} // namespace defs::mocks
