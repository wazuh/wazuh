#include <stdexcept>

#include <fmt/format.h>
#include <pugixml.hpp>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

namespace
{
using xmlModule = std::function<bool(pugi::xml_node&, json::Json&, std::string&)>;
bool xmlWinModule(pugi::xml_node& node, json::Json& docJson, std::string path)
{
    if ("Data" != std::string {node.name()})
    {
        return false;
    }

    path += "/" + std::string {node.attribute("Name").value()};
    docJson.setString(node.text().as_string(), path);

    return true;
}

std::unordered_map<std::string_view, xmlModule> xmlModules = {
    {"default", nullptr},
    {"windows", xmlWinModule},
};

void xmlToJson(pugi::xml_node& docXml,
               json::Json& docJson,
               xmlModule mod,
               std::string path = "")
{
    // TODO: add array support
    // Iterate over the xml generating the corresponding json
    for (auto node : docXml.children())
    {
        // Ignore text nodes as they are handled by the parent
        if (node.type() == pugi::node_pcdata)
        {
            continue;
        }

        std::string localPath {path};

        // Check if we have special rules and if are applied
        auto processed = false;
        if (mod)
        {
            processed = mod(node, docJson, localPath);
        }

        if (!processed)
        {
            localPath += "/" + std::string {node.name()};
            docJson.setObject(localPath);

            auto text = node.text();
            if (!text.empty())
            {
                docJson.setString(text.as_string(), localPath + "/#text");
            }

            for (auto attr : node.attributes())
            {
                docJson.setString(attr.value(), localPath + "/@" + attr.name());
            }
        }

        // Process children
        if (!node.first_child().empty())
        {
            xmlToJson(node, docJson, mod, localPath);
        }
    }
}
} // namespace
namespace hlp
{

parsec::Parser<json::Json> getXMLParser(const std::string& name, const Stop& endTokens, const Options& lst)
{
    if (endTokens.empty())
    {
        throw std::runtime_error(fmt::format("XML parser requires end token."));
    }

    std::string moduleName;

    if (lst.empty())
    {
        moduleName = "default";
    }
    else if (lst.size() == 1)
    {
        moduleName = lst.at(0);
        if (xmlModules.count(moduleName) == 0)
        {
            throw std::runtime_error(
                fmt::format("XML parser module {} not found.", moduleName));
        }
    }
    else
    {
        throw std::runtime_error(fmt::format("XML parser requires 0 or 1 arguments."));
    }

    xmlModule moduleFn = xmlModules[moduleName];

    return [moduleFn, endTokens, name](std::string_view text, int index)
    {
        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            auto& err = std::get<parsec::Result<json::Json>>(res);
            return parsec::makeError<json::Json>(
                fmt::format("{}: {}", name, err.trace().message().value()),
                err.trace().index());
        }

        auto fp = std::get<std::string_view>(res);
        auto pos = fp.size() + index;

        pugi::xml_document xmlDoc;
        json::Json jsonDoc;

        auto parseResult = xmlDoc.load_buffer(fp.data(), fp.size());

        if (parseResult.status == pugi::status_ok)
        {
            xmlToJson(xmlDoc, jsonDoc, moduleFn);

            return parsec::makeSuccess<json::Json>(std::move(jsonDoc), pos);
        }

        return parsec::makeError<json::Json>(
            fmt::format("{}: {}", name, parseResult.description()), index);
    };
}
} // namespace hlp
