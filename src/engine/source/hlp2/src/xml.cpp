#include "fmt/format.h"
#include <hlp/parsec.hpp>
#include <pugixml.hpp>
#include <json/json.hpp>

using Stop = std::optional<std::string>;
using Options = std::vector<std::string>;


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

parsec::Parser<json::Json> getXMLParser(Stop str, Options lst)
{

    bool isWin = lst.empty();

    return [isWin,str](std::string_view text, int index)
    {
        size_t pos = text.size();
        std::string_view fp = text;
        if (str.has_value() && ! str.value().empty())
        {
            pos = text.find(str.value(), index);
            if (pos == std::string::npos)
            {
                return parsec::makeError<json::Json>(
                    fmt::format("Unable to stop at '{}' in input", str.value()), text, index);
            }
            fp = text.substr(index, pos);
        }

        pugi::xml_document xmlDoc;
        json::Json jsonDoc;

        auto parseResult = xmlDoc.load_buffer(fp.data(), fp.size());

        if (parseResult.status == pugi::status_ok)
        {
            if (isWin)
                xmlToJson(xmlDoc, jsonDoc, xmlWinModule);
            else
                xmlToJson(xmlDoc, jsonDoc, nullptr);

            return parsec::makeSuccess<json::Json>(jsonDoc, text, pos);
        }

        return parsec::makeError<json::Json>(fmt::format("{}", parseResult.description()), text, index);
    };
}
} // hlp namespace
