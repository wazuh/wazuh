#ifndef _CATALOG_SHARED_DEF_H
#define _CATALOG_SHARED_DEF_H

#include <string>

/*
 * The catalog shared defines.
 */

//! @brief Assets types.
enum class AssetType
{
    Decoder,
    Rule,
    Output,
    Filter,
    Schema,
    Environment
};

AssetType stringToAssetType(const std::string & name);

#endif // _CATALOGSHAREDDEF_H
