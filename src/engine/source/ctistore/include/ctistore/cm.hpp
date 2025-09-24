#ifndef _CTI_STORE_CM
#define _CTI_STORE_CM

#include <ctistore/icmreader.hpp>

namespace cti::store
{

// TODO: Documentation
class ContentManager : public ICMReader
{
public:
    ContentManager() = default;
    ~ContentManager() override = default;

    /************************************************************************************
     * ICMReader interface implementation
     ************************************************************************************/

    /** @copydoc ICMReader::getAssetList */
    std::vector<base::Name> getAssetList(cti::store::AssetType type) const override;

    /** @copydoc ICMReader::getAsset */
    json::Json getAsset(const base::Name& name) const override;

    /** @copydoc ICMReader::assetExists */
    bool assetExists(const base::Name& name) const override;

    /** @copydoc ICMReader::listKVDB */
    std::vector<std::string> listKVDB() const override;

    /** @copydoc ICMReader::listKVDB */
    std::vector<std::string> listKVDB(const base::Name& integrationName) const override;

    /** @copydoc ICMReader::kvdbExists */
    bool kvdbExists(const std::string& kdbName) const override;

    /** @copydoc ICMReader::kvdbDump */
    json::Json kvdbDump(const std::string& kdbName) const override;

    /** @copydoc ICMReader::getPolicyIntegrationList */
    std::vector<base::Name> getPolicyIntegrationList() const override;

    /** @copydoc ICMReader::getPolicyDefaultParent */
    base::Name getPolicyDefaultParent() const override;


    /************************************************************************************
     * Other public methods or other interfaces can be added here
     ************************************************************************************/
};

} // namespace cti::store

#endif // _CTI_STORE_CM
