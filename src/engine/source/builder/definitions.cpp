#include "definitions.hpp"

#include <algorithm>

#include <fmt/format.h>

namespace builder
{
namespace internals
{

void substituteDefinitions(base::Document& asset)
{
    if (!asset.m_doc.IsObject())
    {
        throw std::runtime_error(fmt::format(
            "Expected [object], got [{}] in substitute definitions function",
            asset.m_doc.GetType()));
    }

    auto definitions = asset.m_doc.FindMember("definitions");
    if (definitions == asset.m_doc.MemberEnd())
    {
        return;
    }

    if (!definitions->value.IsObject())
    {
        throw std::runtime_error(
            fmt::format("Expected definitions to be an object, got [{}]",
                        definitions->value.GetType()));
    }
    auto definitionsObject = definitions->value.GetObject();
    std::unordered_map<std::string, base::Document> definitionsMap;
    for (auto it = definitionsObject.MemberBegin();
         it != definitionsObject.MemberEnd();
         ++it)
    {
        definitionsMap["$" + std::string(it->name.GetString())] = base::Document {it->value};
    }

    asset.m_doc.RemoveMember("definitions");

    std::string jsonString = asset.str();
    for (auto& pair : definitionsMap)
    {
        std::string valueStr = [&]() -> std::string
        {
            if (pair.second.m_doc.IsString())
            {
                return pair.second.m_doc.GetString();
            }
            else if (pair.second.m_doc.IsNumber())
            {
                return std::to_string(pair.second.m_doc.GetInt());
            }
            else
            {
                throw std::runtime_error(
                    fmt::format("Expected [string] or [number], got [{}] in "
                                "substitute definitions function",
                                pair.second.m_doc.GetType()));
            }
        }();

        auto index = 0;
        while (true)
        {
            index = jsonString.find(pair.first, index);
            if (index == std::string::npos)
            {
                break;
            }
            jsonString.replace(index, pair.first.size(), valueStr);
            index += valueStr.size();
        }
    }

    asset = base::Document {jsonString.c_str()};
}

} // namespace internals
} // namespace builder
