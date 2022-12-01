#include <stdexcept>

#include <fmt/format.h>
#include <pugixml.hpp>

#include <hlp/base.hpp>
#include <hlp/hlp.hpp>
#include <hlp/parsec.hpp>
#include <json/json.hpp>

using xmlModule = std::function<bool(pugi::xml_node&, json::Json&, std::string&)>;
static bool xmlWinModule(pugi::xml_node& node, json::Json& docJson, std::string path)
{
    if ("Data" != std::string {node.name()})
    {
        return false;
    }

    path += "/" + std::string {node.attribute("Name").value()};
    docJson.setString(node.text().as_string(), path);

    return true;
}

static void xmlToJson(pugi::xml_node& docXml,
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
namespace hlp
{

parsec::Parser<json::Json> getXMLParser(Stop endTokens, Options lst)
{

    if (lst.size() > 1)
    {
        throw std::runtime_error(fmt::format("XML parser requires 0 or 1 arguments."));
    }

    bool notWin = lst.empty();

    return [notWin, endTokens](std::string_view text, int index)
    {
        auto res = internal::preProcess<json::Json>(text, index, endTokens);
        if (std::holds_alternative<parsec::Result<json::Json>>(res))
        {
            return std::get<parsec::Result<json::Json>>(res);
        }

        auto fp = std::get<std::string_view>(res);
        auto pos = fp.size() + index;

        pugi::xml_document xmlDoc;
        json::Json jsonDoc;

        auto parseResult = xmlDoc.load_buffer(fp.data(), fp.size());

        if (parseResult.status == pugi::status_ok)
        {
            if (notWin)
                xmlToJson(xmlDoc, jsonDoc, nullptr);
            else
                xmlToJson(xmlDoc, jsonDoc, xmlWinModule);

            return parsec::makeSuccess<json::Json>(jsonDoc, text, pos);
        }

        return parsec::makeError<json::Json>(
            fmt::format("{}", parseResult.description()), text, index);
    };
}
} // namespace hlp
