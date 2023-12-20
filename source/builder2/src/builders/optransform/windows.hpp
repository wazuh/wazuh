#ifndef _BUILDER_BUILDERS_WINDOWSHELPER_HPP
#define _BUILDER_BUILDERS_WINDOWSHELPER_HPP

#include <kvdb/ikvdbmanager.hpp>

#include "builders/types.hpp"

namespace builder::builders
{
/**
 * @brief Get the Windows Helper Builder object
 *
 * Obtains the helper that maps A SidList to a SidListDesc, where Sid identifiers for common Windows SIDs are replaced
 * by their names.
 * This helpers needs a kvdb where the mappings between the different parts of the SID and the SID names are stored.
 *
 * @param kvdb kvdb manager to obtain the kvdb handler
 * @param kvdbScopeName kvdb scope name
 * @param schema schema
 * @return HelperBuilder
 */
TransformBuilder getWindowsSidListDescHelperBuilder(const std::shared_ptr<kvdbManager::IKVDBManager>& kvdbManager,
                                                    const std::string& kvdbScopeName);

} // namespace builder::builders

#endif // _BUILDER_BUILDERS_WINDOWSHELPER_HPP
