#include "policy.hpp"

#include <stdexcept>

#include <fmt/format.h>

#include "syntax.hpp"

using namespace json;

namespace builder::policy
{

Policy::Policy(const store::Doc& doc, const std::shared_ptr<store::IStoreReader>& store)
{
    readData(doc, store);
}

void Policy::readData(const store::Doc& doc, const std::shared_ptr<store::IStoreReader>& store)
{
    // Get name
    auto name = doc.getString(syntax::policy::PATH_NAME);
    if (!name)
    {
        throw std::runtime_error(
            fmt::format("Could not find policy name string attribute at '{}'", syntax::policy::PATH_NAME));
    }
    m_name = base::Name(name.value());

    // Get hash
    auto hash = doc.getString(syntax::policy::PATH_HASH);
    if (!hash)
    {
        throw std::runtime_error(
            fmt::format("Could not find policy hash string attribute at '{}'", syntax::policy::PATH_HASH));
    }
    m_hash = hash.value();

    // Get default decoder parents
    auto defaultParents = doc.getObject(syntax::policy::PATH_PARENTS);
    if (defaultParents)
    {
        for (const auto& [ns, name] : defaultParents.value())
        {
            auto decoderStr = name.getString();
            if (!decoderStr)
            {
                throw std::runtime_error(fmt::format("Default parent decoder in namespace '{}' is not a string", ns));
            }
            auto decoderName = base::Name(decoderStr.value());
            if (!syntax::name::isDecoder(decoderName))
            {
                throw std::runtime_error(
                    fmt::format("Default parent decoder '{}' in namespace '{}' is not a decoder", ns, decoderName));
            }

            m_defaultParents.emplace(ns, decoderName);
        }
    }

    // Get the assets
    auto assets = doc.getArray(syntax::policy::PATH_ASSETS);
    if (assets)
    {
        for (const auto& asset : assets.value())
        {
            auto assetName = asset.getString();
            if (!assetName)
            {
                throw std::runtime_error(
                    fmt::format("Invalid not string entry in '{}' array", syntax::policy::PATH_ASSETS));
            }

            // Obtain the namespace
            auto ns = store->getNamespace(assetName.value());
            if (!ns)
            {
                throw std::runtime_error(fmt::format("Could not find namespace for asset '{}'", assetName.value()));
            }

            if (m_assets.find(ns.value()) == m_assets.end())
            {
                m_assets.emplace(ns.value(), std::unordered_set<base::Name>());
            }

            m_assets[ns.value()].emplace(assetName.value());
        }
    }
}

} // namespace builder::policy
