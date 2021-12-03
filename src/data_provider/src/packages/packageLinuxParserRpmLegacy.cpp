#include "rpm.h"
#include "packageLinuxDataRetriever.h"
#include "iberkeleyDbWrapper.h"
#include "sharedDefs.h"
#include "berkeleyRpmDbHelper.h"
#include "packageLinuxParserHelper.h"

void getRpmInfoLegacy(std::function<void(nlohmann::json&)> callback)
{
    BerkeleyRpmDBReader db {std::make_shared<BerkeleyDbWrapper>(RPM_DATABASE)};
    auto row = db.getNext();
    // Get the packages from the Berkeley DB.
    while (!row.empty())
    {
        auto package = PackageLinuxHelper::parseRpm(row);
        if (!package.empty())
        {
            callback(package);
        }
        row = db.getNext();
    }
}
